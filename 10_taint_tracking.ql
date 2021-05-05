/**
 * @kind path-problem
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetwordByteSwap extends Expr{
    NetwordByteSwap () {
        exists( MacroInvocation mi|  
            mi.getMacroName().regexpMatch("ntoh(l|ll|s)") and 
            this=mi.getExpr())
    }
}

class Config extends TaintTracking::Configuration{
    Config() {this = "NetworkToMemFuncLength"}
    
    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetwordByteSwap 
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall fc |
            fc.getTarget().getName()="memcpy" and
            sink.asExpr()=fc.getArgument(2) and
            not fc.getArgument(1).isConstant() )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"