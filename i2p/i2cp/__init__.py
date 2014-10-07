from __future__ import absolute_import, division, print_function, unicode_literals
from future import standard_library
standard_library.install_hooks()

try:
    from ._version import __version__, __revision__
except ImportError:
    pass
