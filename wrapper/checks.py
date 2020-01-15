VDSM_MIN_OVIRT = '4.2.4'  # This has to match VDSK_MIN_VERSION!
VDSM_MIN_VERSION = '4.20.31'  # RC4, final


def check_ovirt_version():
    try:
        import rpmUtils.transaction
        import rpmUtils.miscutils
    except ImportError:
        # TODO: use dnf
        print('No rpmUtils package, cannot probe vdsm versions')
        return False

    ts = rpmUtils.transaction.initReadOnlyTransaction()
    match = ts.dbMatch('name', 'vdsm')
    if len(match) >= 1:
        vdsm = match.next()
        res = rpmUtils.miscutils.compareEVR(
            (vdsm['epoch'], vdsm['version'], None),  # Ignore release number
            rpmUtils.miscutils.stringToVersion(VDSM_MIN_VERSION))
        if res >= 0:
            return True
        if vdsm['epoch'] is None:
            vdsm['epoch'] = ''
        print('Version of VDSM on the host: %s%s' %
              (vdsm['epoch'], vdsm['version']))
    print('Minimal required oVirt/RHV version is %s' % VDSM_MIN_OVIRT)
    return False


CHECKS = {
    'ovirt-version': check_ovirt_version,
}
