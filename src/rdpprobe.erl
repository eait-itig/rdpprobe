%%
%% rdpprobe
%% probe an rdp server for liveness
%%
%% Copyright 2012-2015 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(rdpprobe).

-include_lib("rdp_proto/include/x224.hrl").
-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([main/1]).

main(Args) ->
	logger:add_handler(default, logger_std_h, #{type => standard_error}),
	logger:set_primary_config(level, emergency),
	{ok, _} = application:ensure_all_started(rdpprobe),
	OptSpecList = [
		{tls_host, $h, "tls-host", string, "Hostname for certificate checks"},
		{port, $p, "port", {integer, 3389}, "TCP port RDP is running on"},
		{timeout, $t, "timeout", {integer, 1000}, "Timeout in seconds"},
		{warn_credssp, $w, "warn-credssp", {boolean, false}, "Warn if CredSSP is enabled"}
	],
	case getopt:parse(OptSpecList, Args) of
		{ok, {Options, [Host]}} ->
			main_opt(Host, maps:from_list(Options));
		{ok, {_Options, []}} ->
			io:format("rdpprobe: error: host argument required\n"),
			getopt:usage(OptSpecList, "rdpprobe"),
			halt(1);
		{error, {Why, Data}} ->
			io:format("rdpprobe: error: ~s ~p\n", [Why, Data]),
			getopt:usage(OptSpecList, "rdpprobe"),
			halt(1)
	end.

main_opt(Host, Opts) ->
	#{port := Port, timeout := Timeout, warn_credssp := WarnCredSsp} = Opts,
	TlsHost = maps:get(tls_host, Opts, Host),
	Out = probe(Host, TlsHost, Port, Timeout, WarnCredSsp, [ssl, credssp]),
	case Out of
		{ok, String, Args} ->
			io:format("OK: " ++ String ++ "\n", Args), halt(0);
		{warning, String, Args} ->
			io:format("WARNING: " ++ String ++ "\n", Args), halt(1);
		{critical, String, Args} ->
			io:format("CRITICAL: " ++ String ++ "\n", Args), halt(2)
	end.

connect(Host, Port, SockOpts, Timeout) -> connect(Host, Port, SockOpts, Timeout div 3, 3).
connect(Host, Port, SockOpts, Timeout, Attempts) ->
	case gen_tcp:connect(Host, Port, SockOpts, Timeout) of
		R = {ok, _} -> R;
		R = {error, timeout} when Attempts =< 0 -> R;
		{error, timeout} -> connect(Host, Port, SockOpts, Timeout, Attempts - 1);
		Err -> Err
	end.

certstring({utf8String, S}) ->
	{printableString, unicode:characters_to_list(S)};
certstring({printableString, S}) ->
	{printableString, S}.

probe(Host, TlsHost, Port, Timeout, WarnCredSsp, Protocols) ->
	MyNum = crypto:rand_uniform(1000,9000),
	SockOpts = [binary, {packet, tpkt}, {active, true}, {nodelay, true}],
	maybe([
		fun() ->
			R = connect(Host, Port, SockOpts, Timeout),
			case R of
				{ok, Sock} -> {continue, [Sock]};
				Err -> {return, {critical, "error while connecting: ~p", [Err]}}
			end
		end,
		fun(Sock) ->
			Rec = #x224_cr{dst = 0, src = MyNum, rdp_protocols = Protocols},
			{ok, Data} = x224:encode(Rec),
			{ok, Pkt} = tpkt:encode(Data),
			case gen_tcp:send(Sock, Pkt) of
				ok -> {continue, [Sock]};
				Err -> {return, {critical, "error writing to socket: ~p", [Err]}}
			end
		end,
		fun(Sock) ->
			receive
				{tcp, Sock, Bin} ->
					case tpkt:decode(Bin) of
						{ok, Data, <<>>} -> {continue, [Sock, Data]};
						Err -> {return, {critical, "bad tpkt received: ~p", [Err]}}
					end;
				{tcp_closed, Sock} ->
					{return, {critical, "failed to connect: socket closed before x224_cc", []}}
			after Timeout ->
				{return, {critical, "time out: waiting for x224_cc", []}}
			end
		end,
		fun(Sock, Bin) ->
			case x224:decode(Bin) of
				{ok, #x224_cc{dst = MyNum, rdp_status = ok, rdp_selected = [], rdp_flags = Flags}} ->
					gen_tcp:close(Sock),
					{return, {ok, "connected WITHOUT TLS, flags = ~p", [Flags]}};

				{ok, #x224_cc{dst = MyNum, rdp_status = ok, rdp_selected = [ssl], rdp_flags = Flags}} ->
					{continue, [Sock, [ssl]]};
				{ok, #x224_cc{dst = MyNum, rdp_status = ok, rdp_selected = [credssp]}} ->
					{continue, [Sock, [credssp]]};
				{ok, #x224_cc{dst = MyNum, rdp_status = ok, rdp_selected = [ssl,credssp]}} ->
					{continue, [Sock, [ssl,credssp]]};

				{ok, #x224_cc{dst = MyNum, rdp_status = error, rdp_error = ssl_not_allowed}} ->
					gen_tcp:close(Sock),
					{return, probe(Host, TlsHost, Port, Timeout, true, [])};
				{ok, #x224_cc{dst = MyNum, rdp_status = error, rdp_error = Err}} ->
					gen_tcp:close(Sock),
					{return, {critical, "server returned handshake error: ~p", [Err]}};
				{ok, OthPkt} ->
					gen_tcp:close(Sock),
					{return, {critical, "protocol error: got ~p, expected x224_cc", [element(1, OthPkt)]}};
				Err ->
					gen_tcp:close(Sock),
					{return, {critical, "protocol error: failed to decode x224_cc: ~p", [Err]}}
			end
		end,
		fun(Sock, Prots) ->
			ok = inet:setopts(Sock, [{packet, raw}]),
			case ssl:connect(Sock, [{verify, verify_none}]) of
				{ok, SslSock} ->
			        ok = ssl:setopts(SslSock, [binary, {active, true}, {nodelay, true}]),
			        {continue, [Sock, SslSock, Prots]};
			    Err ->
			    	{return, {critical, "failed to establish TLS: ~p", [Err]}}
			end
		end,
		fun(Sock, SslSock, Prots) ->
			{ok, CertBin} = ssl:peercert(SslSock),
			Cert = public_key:pkix_decode_cert(CertBin, otp),
			{ok, CI} = ssl:connection_information(SslSock),
			#{protocol := Ver, selected_cipher_suite := CipherSuite} = maps:from_list(CI),
			#{cipher := CipherName, key_exchange := KeyEx} = CipherSuite,
			Cipher = {CipherName, KeyEx},
			ok = ssl:close(SslSock),
			gen_tcp:close(Sock),

			TBS = Cert#'OTPCertificate'.tbsCertificate,
			#'OTPTBSCertificate'{issuer = Issuer, subject = Subject, validity = Validity} = TBS,
			#'Validity'{notAfter = Expiry} = Validity,
			{rdnSequence, IssuerAttrs} = Issuer,
			{rdnSequence, SubjectAttrs} = Subject,
			[{printableString, IssuerCN}] = [certstring(V) || [#'AttributeTypeAndValue'{type = Type, value = V}] <- IssuerAttrs, Type =:= {2,5,4,3}],
			[{printableString, SubjectCN}] = [certstring(V) || [#'AttributeTypeAndValue'{type = Type, value = V}] <- SubjectAttrs, Type =:= {2,5,4,3}],

			ExpireDT = case Expiry of
				{utcTime, Str} ->
					<<YBin:2/binary, MBin:2/binary, DBin:2/binary, HBin:2/binary, MinBin:2/binary, SBin:2/binary, "Z">> = list_to_binary(Str),
					Year = case binary_to_integer(YBin) of
						N when (N < 70) -> 2000 + N;
						N -> 1900 + N
					end,
					{
						{Year, binary_to_integer(MBin), binary_to_integer(DBin)},
						{binary_to_integer(HBin), binary_to_integer(MinBin), binary_to_integer(SBin)}
					};
				{generalTime, Str} ->
					<<YBin:4/binary, MBin:2/binary, DBin:2/binary, HBin:2/binary, MinBin:2/binary, SBin:2/binary, "Z">> = list_to_binary(Str),
					{
						{binary_to_integer(YBin), binary_to_integer(MBin), binary_to_integer(DBin)},
						{binary_to_integer(HBin), binary_to_integer(MinBin), binary_to_integer(SBin)}
					}
			end,
			ExpireSec = calendar:datetime_to_gregorian_seconds(ExpireDT),
			NowSec = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
			Expired = case (ExpireSec - NowSec) of
				E when E =< 0 -> {true, abs(E) / 24 / 3600};
				E when E < 3*24*3600 -> {soon, E / 24 / 3600};
				E -> {false, E / 24 /3600}
			end,

			CertHostParts = lists:reverse(string:tokens(string:to_lower(SubjectCN), ".")),
			HostParts = lists:reverse(string:tokens(string:to_lower(TlsHost), ".")),
			HostMatch = case strip_common_prefix(CertHostParts, HostParts) of
				{[], []} -> true;
				{["*"], [_]} -> true;
				_ -> {false, SubjectCN}
			end,
			{continue, [Prots, Ver, Cipher, Expired, HostMatch]}
		end,
		fun
			([ssl], Ver, Cipher, {false, Days}, true) ->
				{return, {ok, "connected ~s, valid certificate (expires in ~.1f days), using ~999p", [atom_to_list(Ver), Days, Cipher]}};
			([credssp], Ver, _Cipher, {false, Days}, true) when WarnCredSsp ->
				{return, {warning, "CredSSP/NLA is enabled, but connected ~s, valid certificate", [atom_to_list(Ver)]}};
			([credssp], Ver, Cipher, {false, Days}, true) ->
				{return, {ok, "connected ~s, valid certificate, using ~999p", [atom_to_list(Ver), Cipher]}};
			(_, Ver, _Cipher, {true, Days}, _) ->
				{return, {critical, "~s certificate expired ~.1f days ago", [atom_to_list(Ver), Days]}};
			([credssp], Ver, _Cipher, {soon, Days}, _) when WarnCredSsp ->
				{return, {warning, "CredSSP/NLA is enabled, and ~s certificate will expire in ~.1f days", [atom_to_list(Ver), Days]}};
			(_, Ver, _Cipher, {soon, Days}, _) ->
				{return, {warning, "~s certificate will expire in ~.1f days", [atom_to_list(Ver), Days]}};
			([credssp], Ver, _Cipher, _, {false, CN}) when WarnCredSsp ->
				{return, {warning, "CredSSP/NLA is enabled, and ~s certificate does not match hostname (~p)", [atom_to_list(Ver), CN]}};
			(_, Ver, _Cipher, _, {false, CN}) ->
				{return, {warning, "~s certificate does not match hostname (~p)", [atom_to_list(Ver), CN]}}
		end
	], []).

strip_common_prefix([A | Rest], [A | RestB]) ->
	strip_common_prefix(Rest, RestB);
strip_common_prefix(A, B) ->
	{A, B}.

maybe([], Args) -> error(no_return);
maybe([Fun | Rest], Args) ->
	case apply(Fun, Args) of
		{continue, NewArgs} ->
			maybe(Rest, NewArgs);
		{return, Value} ->
			Value
	end.
