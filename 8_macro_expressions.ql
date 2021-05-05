import cpp
from MacroInvocation mi, Expr e
where mi.getMacro().getName().regexpMatch("ntoh(l|ll|s)")
  and e=mi.getExpr()
select e
