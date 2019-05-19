# Low-level prototyping tool for WireGuard
Framework for testing WireGuard implementations.
Initially designed to run a deterministic sequence of messages. The original
intention was some kind of shell or script file that could describe the test.

Tested with Python 3.7.3 and python-pynacl 1.3.0.

## Usage
See the scenarios directory for examples. Example, open two terminals and run:

    ./wgll.py < scenarios/wireguard-psk-init.txt
    ./wgll.py < scenarios/wireguard-psk-resp.txt

Or open `./wgll.py` directly and execute commands. Some unpolished helper
commands:

    help [filter]   Prints available commands and parameter names.
    print $var      Prints the variable (note, 'print Foo: $var` does not work)
    set             Shows all available variables

## State modifiers
The following operations are available on a "state" (a model of one peer).

* Set remote address (host, port) -> addrL
* Set local address (host, port) -> addrR
* Configure Noise initiator (SpubR, EprivI, SprivI, time, psk) -> StateI0
* Configure Noise responder (EprivR, SprivR, psk) -> StateR0

* Make an initiation message (senderIndexI, StateI0) -> MsgType1
* Send an initiation message (MsgType1, addrR, addrL)
* Wait for an initiation message (addrL) -> MsgType1, addrR
* Process an initiation message (MsgType1, StateR0) -> StateR1

* Make a responder message (MsgType1, senderIndexR, StateR1) -> MsgType2
* Send a responder message (MsgType2, addrR, addrL)
* Wait for a responder message (addrL) -> MsgType2, addrR
* Process a responder message (MsgType2, StateI0) -> StateI1

* Make a cookie reply from R (receiverIndexI, SpubR, nonce, cookie, MsgType1) -> MsgType3
* Make a cookie reply from I (receiverIndexR, SpubI, nonce, cookie, MsgType2) -> MsgType3
* Send a cookie reply (MsgType3, addrR, addrL)
* Wait for a cookie reply (addrL) -> MsgType3, addrR
* Process a cookie reply from R (MsgType3, SpubR) -> cookie
* Process a cookie reply from I (MsgType3, SpubI) -> cookie

* Make a data message from I (receiverIndexR, counter, TsendI, data) -> MsgType4
* Make a data message from R (receiverIndexI, counter, TsendR, data) -> MsgType4
* Send a data message (MsgType4, addrR, addrL)
* Wait for a data message (addrL) -> MsgType4, addrR
* Process a data message from I (MsgType4, TrecvI) -> data
* Process a data message from R (MsgType4, TrecvR) -> data

## Types
Some types are defined for convenience, this makes it easier to pass around a
group of related parameters that are shared between state transitions.

    StateI0 {
        SpubR, EprivI, SprivI, time
    }

    StateR0 {
        EprivR, SprivR, psk
    }

    StateR1 {
        SpubI, time,
        EpubR,
        Trecv, Tsend
    }

    StateI1 {
        Tsend, Trecv
    }

## Caveats
* This implementation is not intended for regular usage. It was written for
  testing implementations and uses fixed, non-random keys and reuses nonces.
  This makes tests reproducible.
* This spaghetti code was written in one day, bugs might be present.
* Cookie reply messages and MAC2 are not yet implemented.

## License
This prototyping tool is published under the MIT license. See the LICENSE file
for more details.
