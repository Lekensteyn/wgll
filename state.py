# State tracking for WireGuard protocol operations.
# Author: Peter Wu <peter@lekensteyn.nl>
# Licensed under the MIT license <http://opensource.org/licenses/MIT>.

import base64
import hashlib
import inspect
import socket
import traceback

from noise_wg import NoiseWG, crypto_scalarmult_base, aead_encrypt, aead_decrypt


def calc_mac1(key, data):
    mac1_key = hashlib.blake2s(b'mac1----' + key.pub).digest()
    return hashlib.blake2s(data, digest_size=16, key=mac1_key).digest()


def is_bytes(value):
    # Check for __bytes__ due to PublicKey / PrivateKey.
    return type(value) == bytes or hasattr(value, '__bytes__')


def to_bytes(data, length, byteorder='big'):
    if not data:
        data = 0
    if type(data) == int:
        if not length:
            # Indeterminate length, just expand it.
            length = (data.bit_length() + 7) // 8
        return data.to_bytes(length, byteorder)
    if type(data) == str:
        data = base64.b64decode(data)
    elif not is_bytes(data):
        raise RuntimeError(f'Expected bytes, got: {data!r}')
    else:
        data = bytes(data)
    if length and len(data) != length:
        print(f'Warning: want {length}, got length {len(data)}: {data!r}')
        traceback.print_stack()
    return data


class Storage:
    def __init__(self, name, spec, variables):
        self.name = name
        self.spec = spec
        self.instances = []
        self.variables = variables

    def add(self, *args, **kwargs):
        return self.add_object(self.spec(*args, **kwargs))

    def add_object(self, obj):
        i = len(self.instances)
        obj.name = f'{self.name}_{i}'
        # De-duplicate
        for obj2 in self.instances:
            if repr(obj2) == repr(obj):
                obj = obj2
                break
        else:
            self.instances.append(obj)
            self.variables[obj.name] = obj
        print(f'{obj.name} = {obj}')
        return obj

    def resolve(self, name):
        if name == None:
            assert self.instances, f'No previous instance found for {self.name}'
            return self.instances[-1]
        assert self.instances, f'No instances found for {name}'
        # XXX maybe this could split the name and directly use it as index.
        for instance in self.instances[::-1]:
            if instance.name == name:
                return instance
        raise RuntimeError(f'Instance name {name} not found')

    def find(self, fn):
        for instance in self.instances[::-1]:
            if fn(instance):
                return instance
        return None


class Base:
    def __repr__(self):
        try:
            fields = self.fields
        except AttributeError:
            fields = list(inspect.signature(self.__init__).parameters)
        params = []
        for field in fields:
            value = getattr(self, field)
            # XXX should repr dump the full values or refer to the state name?
            if hasattr(value, 'name') and False:
                display = getattr(value, 'name')
            elif is_bytes(value):
                # Cannot just check type(value) because of PublicKey.
                value = bytes(value)
                if not value.replace(b'\0', b''):
                    # Simplify display
                    display = None
                elif len(value) > 16:
                    display = repr(base64.b64encode(value).decode('utf8'))
                else:
                    display = "b'%s'" % ''.join('\\x%02x' % x for x in value)
            else:
                display = repr(value)
            params.append(f'{field}={display}')
        params = ', '.join(params)
        return f'{self.__class__.__name__}({params})'


class Address(Base):
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)
        self.address = (self.host, self.port)


class LocalAddress(Address):
    def __init__(self, host, port):
        super().__init__(host, port)
        self._socket = None

    @property
    def socket(self):
        if not self._socket:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self.host, self.port))
            print(f'{self.name}: Created socket {self._socket}')
        return self._socket


class PublicKey:
    def __init__(self, pub):
        self.pub = to_bytes(pub, 32, byteorder='little')

    def __bytes__(self):
        return self.pub

    def __repr__(self):
        return repr(self.pub)


class PrivateKey:
    def __init__(self, priv):
        self.priv = to_bytes(priv, 32, byteorder='little')
        self.pub = PublicKey(crypto_scalarmult_base(self.priv))

    def __bytes__(self):
        return self.priv

    def __repr__(self):
        return repr(self.priv)


class StateI0(Base):
    def __init__(self, SpubR, EprivI, SprivI, time, psk):
        if not SpubR:
            raise RuntimeError('Missing SpubR')
        self.SpubR = PublicKey(SpubR)
        self.EprivI = PrivateKey(EprivI)
        self.SprivI = PrivateKey(SprivI)
        self.time = to_bytes(time, 12)
        self.psk = to_bytes(psk, 32)
        self._compute_hs()

    @property
    def EpubI(self):
        return self.EprivI.pub

    @property
    def SpubI(self):
        return self.SprivI.pub

    def _compute_hs(self):
        hs = NoiseWG()
        # pre-message
        hs.mix_hash(self.SpubR)
        # message from initiator to responder
        hs.mix_hash(self.EpubI)
        hs.mix_key(self.EpubI)
        hs.mix_dh(self.EprivI, self.SpubR)
        self.enc_SpubI = hs.encrypt_and_hash(self.SpubI)
        hs.mix_dh(self.SprivI, self.SpubR)
        self.enc_time = hs.encrypt_and_hash(self.time)
        self.handshake_state = hs


class StateR0(Base):
    def __init__(self, EprivR, SprivR, psk):
        self.EprivR = PrivateKey(EprivR)
        self.SprivR = PrivateKey(SprivR)
        self.psk = to_bytes(psk, 32)

    def EpubI(self):
        return crypto_scalarmult_base(self.EprivR)


class StateI1(Base):
    fields = ['Tsend', 'Trecv']

    def __init__(self, StateI0, EpubR):
        if not StateI0:
            raise RuntimeError('Missing handshake initiation state')
        if not EpubR:
            raise RuntimeError('Missing handshake initiation details')
        self._compute_hs(StateI0, EpubR, StateI0.handshake_state.copy())

    def _compute_hs(self, StateI0, EpubR, hs):
        hs.mix_hash(EpubR)
        hs.mix_key(EpubR)
        hs.mix_dh(StateI0.EprivI, EpubR)
        hs.mix_dh(StateI0.SprivI, EpubR)
        hs.mix_key_and_hash(StateI0.psk)
        self.enc_empty = hs.encrypt_and_hash(b'')
        self.Tsend, self.Trecv = hs.split()


class StateR1(Base):
    # SpubI and time are not really needed by the handshake, but perhaps this
    # could serve as debugging aid.
    fields = ['SpubI', 'time', 'Tsend', 'Trecv']

    def __init__(self, StateR0, EpubI, enc_SpubI, enc_time):
        if not StateR0:
            raise RuntimeError('Missing handshake response state')
        if not EpubI or not enc_SpubI or not enc_time:
            raise RuntimeError('Missing handshake response details')
        self._compute_hs(StateR0, EpubI, enc_SpubI, enc_time)

    def _compute_hs(self, StateR0, EpubI, enc_SpubI, enc_time):
        hs = NoiseWG()
        # pre-message
        hs.mix_hash(StateR0.SprivR.pub)
        # message from initiator to responder
        hs.mix_hash(EpubI)
        hs.mix_key(EpubI)
        hs.mix_dh(StateR0.SprivR, EpubI)
        self.SpubI = PublicKey(hs.decrypt_and_hash(enc_SpubI))
        hs.mix_dh(StateR0.SprivR, self.SpubI)
        self.time = hs.decrypt_and_hash(enc_time)
        # message from responder to initiator
        self.EpubR = StateR0.EprivR.pub
        hs.mix_hash(self.EpubR)
        hs.mix_key(self.EpubR)
        hs.mix_dh(StateR0.EprivR, EpubI)
        hs.mix_dh(StateR0.EprivR, self.SpubI)
        hs.mix_key_and_hash(StateR0.psk)
        self.enc_empty = hs.encrypt_and_hash(b'')
        self.Trecv, self.Tsend = hs.split()


class Data(Base):
    def __init__(self, data):
        self.data = to_bytes(data, 0)


class Field:
    def __init__(self, name, size, constructor=None, fixed=None):
        self.name = name
        self.size = size
        self.fixed = fixed
        if constructor is None:
            def constructor(data): return to_bytes(data, size)
        self._constructor = constructor

    def parse_value(self, value):
        return self._constructor(value)


class Message(Base):
    def __init__(self, *args, **kwargs):
        # Do not expose fixed fields through the constructor.
        self.fields = [f.name for f in self.fields_desc if not f.fixed]
        for i, value in enumerate(args):
            name = self.fields[i]
            assert name not in kwargs, f'Duplicate parameter: {name}'
            kwargs[name] = value
        for f in self.fields_desc:
            val = kwargs.pop(f.name, None)
            val = f.parse_value(val)
            assert not f.size or len(bytes(val)) == f.size, \
                f'Expected size {f.size} for {f.name}, got {len(val)}: {val!r}'
            setattr(self, f.name, val)
        assert not kwargs, f'Unexpected parameters: {kwargs}'

    def __bytes__(self):
        bs = b''
        for f in self.fields_desc:
            val = f.fixed
            if val is None:
                val = bytes(getattr(self, f.name))
            assert not f.size or len(val) == f.size, \
                f'Expected size {f.size} for {f.name}, got {len(val)}: {val!r}'
            bs += val
        return bs

    @classmethod
    def from_bytes(cls, bs):
        min_size = sum(f.size for f in cls.fields_desc)
        assert len(bs) >= min_size, f'Missing data: {len(bs)} < {min_size}'
        fields = {}
        for fs in cls.fields_desc:
            if not fs.size:
                # No explicit size set, consume remaining data
                value, bs = bs, None
            else:
                value, bs = bs[:fs.size], bs[fs.size:]
            # Ignore values in fixed fields.
            if not fs.fixed:
                value = fs.parse_value(value)
                fields[fs.name] = value
        assert not bs, f'Trailing data: {bs}'
        return cls(**fields)


class MsgType1(Message):
    fields_desc = (
        Field('type', 4, fixed=b'\1\0\0\0'),
        Field('sender', 4, lambda x: to_bytes(x, 4, 'little')),
        Field('EpubI', 32, PublicKey),
        Field('enc_SpubI', 48),
        Field('enc_time', 28),
        Field('mac1', 16, fixed=b'\0' * 16),    # overwritten later
        Field('mac2', 16),
    )

    def __init__(self, *args, SpubR=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.SpubR = PublicKey(SpubR)

    def __bytes__(self):
        msg = super().__bytes__()
        msg = msg[:-32]
        msg += calc_mac1(self.SpubR, msg)
        msg += self.mac2
        return msg


class MsgType2(Message):
    fields_desc = (
        Field('type', 4, fixed=b'\2\0\0\0'),
        Field('sender', 4, lambda x: to_bytes(x, 4, 'little')),
        Field('receiver', 4, lambda x: to_bytes(x, 4, 'little')),
        Field('EpubR', 32, PublicKey),
        Field('enc_empty', 16),
        Field('mac1', 16, fixed=b'\0' * 16),    # overwritten later
        Field('mac2', 16),
    )

    def __init__(self, *args, SpubI=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.SpubI = PublicKey(SpubI)

    def __bytes__(self):
        msg = super().__bytes__()
        msg = msg[:-32]
        msg += calc_mac1(self.SpubI, msg)
        msg += self.mac2
        return msg


class MsgType3(Message):
    fields_desc = (
        Field('type', 4, fixed=b'\3\0\0\0'),
        Field('receiver', 4, lambda x: to_bytes(x, 4, 'little')),
        Field('nonce', 24),
        Field('enc_cookie', 32),
    )


class MsgType4(Message):
    fields_desc = (
        Field('type', 4, fixed=b'\4\0\0\0'),
        Field('receiver', 4, lambda x: to_bytes(x, 4, 'little')),
        Field('counter', 8, lambda x: to_bytes(x, 8, 'little')),
        Field('enc_payload', 0),
    )


class State:
    def __init__(self):
        variables = {}
        self.addrL = Storage('addrL', LocalAddress, variables)
        self.addrR = Storage('addrR', Address, variables)
        self.StateI0 = Storage('StateI0', StateI0, variables)
        self.StateI1 = Storage('StateI1', StateI1, variables)
        self.StateR0 = Storage('StateR0', StateR0, variables)
        self.StateR1 = Storage('StateR1', StateR1, variables)
        self.MsgType1 = Storage('MsgType1', MsgType1, variables)
        self.MsgType2 = Storage('MsgType2', MsgType2, variables)
        self.MsgType3 = Storage('MsgType3', MsgType3, variables)
        self.MsgType4 = Storage('MsgType4', MsgType4, variables)
        self.Data = Storage('Data', Data, variables)
        self.variables = {}

    def _wait_for_message(self, what, addrL):
        addrL = self.addrL.resolve(addrL)
        msg_class = what.spec
        print(f'Wait for {msg_class.__name__} on {addrL}')
        # XXX increase this for testing data messages with higher MTU?
        data, address = addrL.socket.recvfrom(4096)
        addrR = self.addrR.add(*address)
        msg = msg_class.from_bytes(data)
        what.add_object(msg)
        return msg, addrR

    def _send_message(self, what, msg, addrR, addrL):
        msg = what.resolve(msg)
        addrR = self.addrR.resolve(addrR)
        addrL = self.addrL.resolve(addrL)
        addrL.socket.sendto(bytes(msg), addrR.address)

    def set_local(self, host, port):
        return self.addrL.add(host, port)

    def set_remote(self, host, port):
        return self.addrR.add(host, port)

    def noise_init(self, SpubR=None, EprivI=None, SprivI=None, time=None, psk=None):
        return self.StateI0.add(SpubR, EprivI, SprivI, time, psk)

    def noise_resp(self, EprivR=None, SprivR=None, psk=None):
        return self.StateR0.add(EprivR, SprivR, psk)

    def make_init(self, sender=None, StateI0=None):
        sender = to_bytes(sender, 4, 'little')
        StateI0 = self.StateI0.resolve(StateI0)
        return self.MsgType1.add(sender, StateI0.EpubI.pub, StateI0.enc_SpubI,
                                 StateI0.enc_time, SpubR=StateI0.SpubR.pub)

    def send_init(self, MsgType1=None, addrR=None, addrL=None):
        self._send_message(self.MsgType1, MsgType1, addrR, addrL)

    def wait_for_init(self, addrL=None):
        return self._wait_for_message(self.MsgType1, addrL)

    def process_init(self, MsgType1=None, StateR0=None):
        MsgType1 = self.MsgType1.resolve(MsgType1)
        StateR0 = self.StateR0.resolve(StateR0)
        return self.StateR1.add(StateR0, MsgType1.EpubI, MsgType1.enc_SpubI,
                                MsgType1.enc_time)

    def make_resp(self, MsgType1=None, sender=None, StateR1=None):
        MsgType1 = self.MsgType1.resolve(MsgType1)
        receiver = MsgType1.sender
        sender = to_bytes(sender, 4, 'little')
        StateR1 = self.StateR1.resolve(StateR1)
        return self.MsgType2.add(sender, receiver, StateR1.EpubR.pub,
                                 StateR1.enc_empty,
                                 SpubI=StateR1.SpubI.pub)

    def send_resp(self, MsgType2=None, addrR=None, addrL=None):
        self._send_message(self.MsgType2, MsgType2, addrR, addrL)

    def wait_for_resp(self, addrL=None):
        return self._wait_for_message(self.MsgType2, addrL)

    def process_resp(self, MsgType2=None, StateI0=None):
        MsgType2 = self.MsgType2.resolve(MsgType2)
        StateI0 = self.StateI0.resolve(StateI0)
        return self.StateI1.add(StateI0, MsgType2.EpubR)

    def _make_data(self, receiver=None, counter=None, Tsend=None, data=None):
        receiver = to_bytes(receiver, 4, 'little')
        counter = to_bytes(counter, 8, 'little')
        assert len(Tsend) == 32
        data = data or b''
        nonce = int.from_bytes(counter, 'little')
        enc_data = aead_encrypt(Tsend, nonce, data, b'')
        return self.MsgType4.add(receiver, counter, enc_data)

    def make_data_as_init(self, receiver=None, counter=None, TsendI=None, data=None):
        StateI1 = self.StateI1.resolve(TsendI)
        return self._make_data(receiver, counter, StateI1.Tsend, data)

    def make_data_as_resp(self, receiver=None, counter=None, TsendR=None, data=None):
        StateR1 = self.StateR1.resolve(TsendR)
        return self._make_data(receiver, counter, StateR1.Tsend, data)

    def send_data(self, MsgType4=None, addrR=None, addrL=None):
        self._send_message(self.MsgType4, MsgType4, addrR, addrL)

    def wait_for_data(self, addrL=None):
        return self._wait_for_message(self.MsgType4, addrL)

    def _process_data(self, MsgType4=None, Trecv=None):
        assert len(Trecv) == 32
        MsgType4 = self.MsgType4.resolve(MsgType4)
        nonce = int.from_bytes(MsgType4.counter, 'little')
        data = aead_decrypt(Trecv, nonce, MsgType4.enc_payload, b'')
        return self.Data.add(data)

    def process_data_as_init(self, MsgType4=None, TrecvI=None):
        StateI1 = self.StateI1.resolve(TrecvI)
        return self._process_data(MsgType4, StateI1.Trecv)

    def process_data_as_resp(self, MsgType4=None, TrecvR=None):
        StateR1 = self.StateR1.resolve(TrecvR)
        return self._process_data(MsgType4, StateR1.Trecv)
