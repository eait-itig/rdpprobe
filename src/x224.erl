%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright (c) 2012, The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%

-module(x224).

-include("x224.hrl").

-export([encode/1, decode/1, pretty_print/1]).


-define(PDU_CR, 2#1110).
-define(PDU_CC, 2#1101).
-define(PDU_DR, 2#1000).
-define(PDU_AK, 2#0110).
-define(PDU_DT, 2#1111).

-define(RDP_NEGREQ, 16#01).
-define(RDP_NEGRSP, 16#02).
-define(RDP_NEGFAIL, 16#03).

-define(pp(Rec),
pretty_print(Rec, N) ->
    N = record_info(size, Rec) - 1,
    record_info(fields, Rec)).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).
?pp(x224_cr);
?pp(x224_cc);
?pp(x224_dt);
?pp(x224_dr);
pretty_print(_, _) ->
    no.

-define(negflags, [{skip,4},restricted_admin,negrsp,dynvc_gfx,extdata]).

-spec encode(Record :: term()) -> {ok, binary()} | {error, term()}.
encode(Record) ->
    case Record of
        #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie, rdp_protocols = Protocols} ->
            Head = <<?PDU_CR:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,
            CookiePart = if is_binary(Cookie) and not (Cookie =:= <<>>) ->
                <<Cookie/binary, 16#0d0a:16/big>>;
            is_list(Cookie) and not (Cookie =:= []) ->
                Bin = list_to_binary(Cookie),
                <<Bin/binary, 16#0d0a:16/big>>;
            true ->
                <<>>
            end,

            Prots = rdpp:encode_protocol_flags(Protocols),
            RdpPart = <<?RDP_NEGREQ:8, 0:8, 8:16/little, Prots:32/little>>,

            LI = byte_size(Head) + byte_size(CookiePart) + byte_size(RdpPart),
            {ok, <<LI:8, Head/binary, CookiePart/binary, RdpPart/binary>>};

        #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status = error, rdp_error = Error} ->
            Head = <<?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,
            Code = case Error of
                ssl_required -> 16#01;
                ssl_not_allowed -> 16#02;
                cert_not_on_server -> 16#03;
                bad_flags -> 16#04;
                credssp_required -> 16#05;
                ssl_with_user_auth_required -> 16#06;
                _ -> 0
            end,
            RdpPart = <<?RDP_NEGFAIL:8, 0:8, 8:16/little, Code:32/little>>,

            LI = byte_size(Head) + byte_size(RdpPart),
            {ok, <<LI:8, Head/binary, RdpPart/binary>>};

        #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status=ok, rdp_flags = Flags, rdp_selected = Protocols} ->
            Head = <<?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, 0:1, 0:1>>,

            Prots = rdpp:encode_protocol_flags(Protocols),
            Flags2 = rdpp:encode_bit_flags(sets:from_list(Flags), ?negflags),
            RdpPart = <<?RDP_NEGRSP:8, Flags2/binary, 8:16/little, Prots:32/little>>,

            LI = byte_size(Head) + byte_size(RdpPart),
            {ok, <<LI:8, Head/binary, RdpPart/binary>>};

        #x224_dt{roa = ROA, eot = EOT, tpdunr = TpduNr, data = Data} ->
            Head = <<?PDU_DT:4, 0:3, ROA:1, EOT:1, TpduNr:7>>,
            LI = byte_size(Head),
            {ok, <<LI:8, Head/binary, Data/binary>>};

        #x224_dr{dst = DstRef, src = SrcRef, reason = Error} ->
            Reason = case Error of
                not_specified -> 0;
                congestion -> 1;
                not_attached -> 2;
                address_unknown -> 3;
                _ -> 0
            end,
            Head = <<?PDU_DR:4, 0:4, DstRef:16/big, SrcRef:16/big, Reason:8>>,
            LI = byte_size(Head),
            {ok, <<LI:8, Head/binary>>};

        _ ->
            {error, bad_x224}
    end.

-spec decode(Data :: binary()) -> {ok, term()} | {error, term()}.
decode(Data) ->
    case Data of
        <<LI:8, ?PDU_CR:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, ExtFmts:1, ExFlow:1, Rest/binary>> ->
            {Cookie, RdpData} = case binary:match(Rest, <<16#0d0a:16/big>>) of
                {Pos, _} ->
                    <<Token:Pos/binary-unit:8, 16#0d0a:16/big, Rem/binary>> = Rest,
                    {Token, Rem};
                _ ->
                    {none, Rest}
            end,
            case RdpData of
                <<?RDP_NEGREQ:8, Flags:8, _Length:16/little, Protocols:32/little>> ->
                    Prots = rdpp:decode_protocol_flags(Protocols),
                    {ok, #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie, rdp_protocols = Prots}};
                _ ->
                    {ok, #x224_cr{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_cookie = Cookie}}
            end;

        <<LI:8, ?PDU_CC:4, Cdt:4, DstRef:16/big, SrcRef:16/big, Class:4, 0:2, ExtFmts:1, ExFlow:1, Rest/binary>> ->
            case Rest of
                <<?RDP_NEGRSP:8, Flags:1/binary, _Length:16/little, Selected:32/little>> ->
                    FlagSet = rdpp:decode_bit_flags(Flags, ?negflags),
                    Prots = rdpp:decode_protocol_flags(Selected),
                    {ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_flags = sets:to_list(FlagSet), rdp_selected = Prots}};

                <<?RDP_NEGFAIL:8,  _Flags:8, _Length:16/little, Code:32/little>> ->
                    Error = case Code of
                        16#01 -> ssl_required;
                        16#02 -> ssl_not_allowed;
                        16#03 -> cert_not_on_server;
                        16#04 -> bad_flags;
                        16#05 -> credssp_required;
                        16#06 -> ssl_with_user_auth_required;
                        _ -> unknown
                    end,
                    {ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_status = error, rdp_error = Error}};

                _ ->
                    {ok, #x224_cc{src = SrcRef, dst = DstRef, class = Class, cdt = Cdt, rdp_selected = []}}
            end;

        <<LI:8, ?PDU_DT:4, 0:3, ROA:1, EOT:1, TpduNr:7, Rest/binary>> when LI == 2 ->
            {ok, #x224_dt{roa = ROA, eot = EOT, tpdunr = TpduNr, data = Rest}};

        <<LI:8, ?PDU_DR:4, 0:4, DstRef:16/big, SrcRef:16/big, Reason:8, Rest/binary>> ->
            Error = case Reason of
                0 -> not_specified;
                1 -> congestion;
                2 -> not_attached;
                3 -> address_unknown;
                _ -> unknown
            end,
            {ok, #x224_dr{dst = DstRef, src = SrcRef, reason = Error}};

        _ ->
            {error, bad_x224}
    end.
