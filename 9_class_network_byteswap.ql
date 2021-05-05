import cpp
class NetworkByteSwap extends Expr{
    NetworkByteSwap () {
        exists( MacroInvocation mi|
            mi.getMacro().getName().regexpMatch("ntoh(l|ll|s)") and
            this=mi.getExpr())
    }
}

from NetworkByteSwap nbs
select nbs