%%
%% rdpprobe
%% probe an rdp server for liveness
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(check_rdp).

-include("x224.hrl").
-include("rdpp.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([main/1]).

main(Args) ->
	Opts = [
		{tls_host, "h", "tls-host", string},
		{port, "p", "port", integer},
		{timeout, "t", "timeout", integer},
		{warn_credssp, "w", "warn-credssp", false}
	],
	Args2 = getopt(Args, Opts, []),
	{OptArgs, ArgArgs} = lists:partition(fun(K) -> is_tuple(K) end, lists:reverse(Args2)),
	main_opt(ArgArgs, OptArgs).

main_opt([Host], Opts) ->
	Port = proplists:get_value(port, Opts, 3389),
	TlsHost = proplists:get_value(tls_host, Opts, Host),
	Timeout = proplists:get_value(timeout, Opts, 1000),
	WarnCredSsp = proplists:get_value(warn_credssp, Opts, false),
	error_logger:tty(false),
	[ok = application:start(X) || X <- [crypto,asn1,public_key,ssl]],
	Out = probe(Host, TlsHost, Port, Timeout, WarnCredSsp, [ssl, credssp]),
	case Out of
		{ok, String, Args} ->
			io:format("OK: " ++ String ++ "\n", Args), halt(0);
		{warning, String, Args} ->
			io:format("WARNING: " ++ String ++ "\n", Args), halt(1);
		{critical, String, Args} ->
			io:format("CRITICAL: " ++ String ++ "\n", Args), halt(2)
	end;

main_opt(_, _) ->
	usage().

usage() ->
	io:format("usage: check_rdp [opts] <host or ip>\n"),
	io:format("\noptions:\n"),
	io:format("  -h|--tls-host hostname\n"),
	io:format("      use a different hostname for the TLS certificate check\n"),
	io:format("  -p|--port port (default 3389)\n"),
	io:format("  -t|--timeout ms (default 1000)\n"),
	io:format("  -w|--warn-credssp\n"),
	halt(3).

connect(Host, Port, SockOpts, Timeout) -> connect(Host, Port, SockOpts, Timeout div 3, 3).
connect(Host, Port, SockOpts, Timeout, Attempts) ->
	case gen_tcp:connect(Host, Port, SockOpts, Timeout) of
		R = {ok, _} -> R;
		R = {error, timeout} when Attempts =< 0 -> R;
		{error, timeout} -> connect(Host, Port, SockOpts, Timeout, Attempts - 1);
		Err -> Err
	end.

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
			{ok, {Ver, Cipher}} = ssl:connection_info(SslSock),
			ok = ssl:close(SslSock),
			gen_tcp:close(Sock),

			TBS = Cert#'OTPCertificate'.tbsCertificate,
			#'OTPTBSCertificate'{issuer = Issuer, subject = Subject, validity = Validity} = TBS,
			#'Validity'{notAfter = Expiry} = Validity,
			{rdnSequence, IssuerAttrs} = Issuer,
			{rdnSequence, SubjectAttrs} = Subject,
			[{printableString, IssuerCN}] = [V || [#'AttributeTypeAndValue'{type = Type, value = V}] <- IssuerAttrs, Type =:= {2,5,4,3}],
			[{printableString, SubjectCN}] = [V || [#'AttributeTypeAndValue'{type = Type, value = V}] <- SubjectAttrs, Type =:= {2,5,4,3}],

			Expired = case Expiry of
				{utcTime, Str} ->
					Time = case string:to_integer(Str) of
						{T, "Z"} -> {T div 1000000, T rem 1000000, 0}
					end,
					case timer:now_diff(os:timestamp(), Time) of
						N when N >= 0 -> {true, N / 1000000};
						N when abs(N) < 30*24*3600*1000000 -> {soon, abs(N) / 1000000};
						N -> false
					end
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
			([ssl], Ver, Cipher, false, true) ->
				{return, {ok, "connected ~s, valid certificate, using ~p", [atom_to_list(Ver), Cipher]}};
			([credssp], Ver, _Cipher, false, true) when WarnCredSsp ->
				{return, {warning, "CredSSP/NLA is enabled, but connected ~s, valid certificate", [atom_to_list(Ver)]}};
			([credssp], Ver, Cipher, false, true) ->
				{return, {ok, "connected ~s, valid certificate, using ~p", [atom_to_list(Ver), Cipher]}};
			(_, Ver, _Cipher, {true, Secs}, _) ->
				Days = Secs / (24*3600),
				{return, {critical, "~s certificate expired ~.1f days ago", [atom_to_list(Ver), Days]}};
			([credssp], Ver, _Cipher, {soon, Secs}, _) when WarnCredSsp ->
				Days = Secs / (24*3600),
				{return, {warning, "CredSSP/NLA is enabled, and ~s certificate will expire in ~.1f days", [atom_to_list(Ver), Days]}};
			(_, Ver, _Cipher, {soon, Secs}, _) ->
				Days = Secs / (24*3600),
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

getopt([], _Opts, Args) -> Args;
getopt([[$-, $- | K], V | Rest], Opts, Args) ->
	case lists:keyfind(K, 3, Opts) of
		{Atom, _Short, K, string} ->
			getopt(Rest, Opts, [{Atom, V} | Args]);
		{Atom, _Short, K, integer} ->
			getopt(Rest, Opts, [{Atom, list_to_integer(V)} | Args]);
		{Atom, _Short, K, Type} when (Type =:= false) or (Type =:= undefined) ->
			getopt([V | Rest], Opts, [{Atom, true} | Args]);
		false ->
			io:format("unknown option --~s\n", [K]),
			usage()
	end;
getopt([[$-, $- | K] | Rest], Opts, Args) ->
	case lists:keyfind(K, 3, Opts) of
		{Atom, _Short, K, Type} when (Type =:= false) or (Type =:= undefined) ->
			getopt(Rest, Opts, [{Atom, true} | Args]);
		_ ->
			io:format("unknown option --~s\n", [K]),
			usage()
	end;
getopt([[$- | K], V | Rest], Opts, Args) ->
	case lists:keyfind(K, 2, Opts) of
		{Atom, K, _Long, string} ->
			getopt(Rest, Opts, [{Atom, V} | Args]);
		{Atom, K, _Long, integer} ->
			getopt(Rest, Opts, [{Atom, list_to_integer(V)} | Args]);
		{Atom, K, _Long, Type} when (Type =:= false) or (Type =:= undefined) ->
			getopt([V | Rest], Opts, [{Atom, true} | Args]);
		false ->
			io:format("unknown option -~s\n", [K]),
			usage()
	end;
getopt([[$- | K] | Rest], Opts, Args) ->
	case lists:keyfind(K, 3, Opts) of
		{Atom, _Short, K, Type} when (Type =:= false) or (Type =:= undefined) ->
			getopt(Rest, Opts, [{Atom, true} | Args]);
		_ ->
			io:format("unknown option -~s\n", [K]),
			usage()
	end;
getopt([Next | Rest], Opts, Args) ->
	getopt(Rest, Opts, [Next | Args]).
