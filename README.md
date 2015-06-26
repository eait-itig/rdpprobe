Nagios/Icinga-compatible probe for MS Remote Desktop servers.

Rather than just check that you can open a TCP socket to the RDP server, this probe also checks that the lower layers of the RDP protocol stack (tpkt, X224, MCS-GCC) can initialise and connect, and also validates the TLS certificate for the server (if CredSSP is enabled).

It can also be used to emit a warning if the RDP server has CredSSP disabled.

## Usage

    usage: check_rdp [opts] <host or ip>

    options:
      -h|--tls-host hostname
          use a different hostname for the TLS certificate check
      -p|--port port (default 3389)
      -t|--timeout ms (default 1000)
      -w|--warn-credssp

You can add it to nagios/icinga with a command block like this:

    define command{
            command_name    check_rdp
            command_line    $USER1$/check_rdp -h $ARG1$ -t 5000 $HOSTADDRESS$
            }

## License

2-clause BSD

## Compiling

Install Erlang and rebar, then

    rebar get-deps && rebar compile && rebar escriptize
