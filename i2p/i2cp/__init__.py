from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_hooks()

try:
    from ._version import __version__, __revision__
except ImportError:
    pass
