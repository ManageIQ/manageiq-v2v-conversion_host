from .hosts import BaseHost


def check_rhv_guest_tools():
    """
    Make sure there is ISO domain with at least one ISO with windows drivers.
    Preferably RHV Guest Tools ISO.
    """
    host = BaseHost.factory(BaseHost.TYPE_VDSM)
    data = {'install_drivers': True}
    host.check_install_drivers(data)
    return ('virtio_win' in data)


CHECKS = {
    'rhv-guest-tools': check_rhv_guest_tools,
}
