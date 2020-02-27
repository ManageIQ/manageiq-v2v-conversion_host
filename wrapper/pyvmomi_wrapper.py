"Simple wrapper for all pyvmomi imports"

from pyVim import connect, task
import pyVmomi

SmartConnect = connect.SmartConnect
SmartConnectNoSSL = connect.SmartConnectNoSSL
Disconnect = connect.Disconnect
WaitForTask = task.WaitForTask

# pylint: disable=no-member; dynamic module
vim = pyVmomi.vim
