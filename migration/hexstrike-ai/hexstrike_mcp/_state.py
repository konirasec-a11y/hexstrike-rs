"""Monolith global semantics: rebind a name across every package module."""
import sys


def set_global(name, value):
    """Rebind `name` to `value` in all modules of this package.

    Replicates the original single-file behaviour where an assignment inside
    the main block was visible to every function, no matter its section.
    """
    pkg = __name__.rsplit('.', 1)[0]
    prefix = pkg + '.'
    for modname, mod in list(sys.modules.items()):
        if modname == pkg or modname.startswith(prefix):
            d = getattr(mod, '__dict__', None)
            if d is not None:
                d[name] = value
