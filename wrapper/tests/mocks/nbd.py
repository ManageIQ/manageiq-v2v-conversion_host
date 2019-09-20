# pylint: skip-file
"Module for mocking nbd due to temporary unavailability in pipy"


STATE_HOLE = 1
STATE_ZERO = 2


class Buffer:
    pass


class NBD:

    def add_meta_context(self, ctx):
        pass

    def connect_uri(self, uri):
        pass

    def get_version(self):
        pass

    def shutdown(self):
        pass
