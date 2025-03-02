from py2neo import Graph, NodeMatcher
from angr import SimState, Project
from angr.sim_manager import SimulationManager
import re
from typing import Dict, Any, List, Optional
import logging
from enum import Enum

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class QueryType(Enum):
    """支持的查询类型"""
    CYPHER = "cypher"
    SEMANTIC = "semantic"
    DATAFLOW = "dataflow"
    CONSTRAINED_PATH = "constrained_path"
    VISUALIZATION = "visualization"


class InvalidParameterError(ValueError):
    """自定义参数错误异常"""
    pass


class QueryParams:
    """增强型通用查询参数容器

    参数验证规则：
    - 地址参数必须为16进制字符串或整数
    - 正则表达式必须为合法RE
    - 深度参数必须>0
    """

    def __init__(self,
                 query_type: QueryType,
                  ** kwargs):
        self.query_type = query_type

        # 动态参数存储
        self.params = {
            'cypher_pattern': kwargs.get('cypher_pattern', ''),
            'cypher_params': kwargs.get('cypher_params', {}),
            'instructions_regex': kwargs.get('instructions_regex', '.*'),
            'constraints_regex': kwargs.get('constraints_regex', '.*'),
            'var_name': kwargs.get('var_name', ''),
            'max_depth': kwargs.get('max_depth', 5),
            'start_addr': self._parse_address(kwargs.get('start_addr', 0)),
            'end_addr': self._parse_address(kwargs.get('end_addr', 0)),
            'constraints': kwargs.get('constraints', []),
            'path_addrs': [self._parse_address(addr) for addr in kwargs.get('path_addrs', [])]
        }

    def __getattr__(self, name):
        """动态获取参数"""
        if name in self.params:
            return self.params[name]
        raise AttributeError(f"参数 {name} 不存在")

    def _parse_address(self, addr) -> int:
        """地址解析统一处理"""
        if isinstance(addr, int):
            return addr
        try:
            return int(addr, 16) if isinstance(addr, str) else int(addr)
        except ValueError:
            raise InvalidParameterError(f"无效地址格式: {addr}")

    def validate(self):
        """类型安全验证"""
        validation_rules = {
            QueryType.CYPHER: [
                ('cypher_pattern', str),
                ('cypher_params', dict)
            ],
            QueryType.SEMANTIC: [
                ('instructions_regex', str),
                ('constraints_regex', str)
            ],
            QueryType.DATAFLOW: [
                ('var_name', str),
                ('max_depth', int)
            ],
            QueryType.CONSTRAINED_PATH: [
                ('start_addr', int),
                ('end_addr', int),
                ('constraints', list)
            ],
            QueryType.VISUALIZATION: [
                ('path_addrs', list)
            ]
        }

        # 类型检查
        for param, expected_type in validation_rules[self.query_type]:
            value = getattr(self, param)
            if not isinstance(value, expected_type):
                raise InvalidParameterError(
                    f"参数 {param} 类型错误，应为 {expected_type}，实际为 {type(value)}"
                )

        # 特殊规则验证
        if self.query_type == QueryType.DATAFLOW and self.max_depth <= 0:
            raise InvalidParameterError("max_depth 必须大于0")

        if self.query_type == QueryType.SEMANTIC:
            try:
                re.compile(self.instructions_regex)
                re.compile(self.constraints_regex)
            except re.error as e:
                raise InvalidParameterError(f"无效正则表达式: {str(e)}")


class SPDGQueryEngine:
    def __init__(self, neo4j_graph: Graph, angr_project: Optional[Project] = None):
        self.neo4j = neo4j_graph
        self.matcher = NodeMatcher(neo4j_graph)
        self.proj = angr_project
        self._query_cache = {}  # 查询缓存

    def execute_query(self, params: QueryParams) -> List[Dict[str, Any]]:
        """统一查询入口方法"""
        params.validate()

        try:
            if params.query_type == QueryType.CYPHER:
                return self._execute_cypher(params)
            elif params.query_type == QueryType.SEMANTIC:
                return self._execute_semantic(params)
            elif params.query_type == QueryType.DATAFLOW:
                return self._execute_dataflow(params)
            elif params.query_type == QueryType.CONSTRAINED_PATH:
                return self._execute_constrained_path(params)
            elif params.query_type == QueryType.VISUALIZATION:
                return [{"dot": self._generate_visualization(params)}]
        except Exception as e:
            logger.error(f"查询执行失败: {str(e)}")
            raise

    def _execute_cypher(self, params: QueryParams) -> List[Dict[str, Any]]:
        """执行原始Cypher查询"""
        logger.info(f"执行Cypher查询: {params.cypher_pattern[:50]}...")
        return self.neo4j.run(params.cypher_pattern, params.cypher_params).data()

    def _execute_semantic(self, params: QueryParams) -> List[Dict[str, Any]]:
        """执行语义查询"""
        query = """
        MATCH (b:Block)
        WHERE b.instructions =~ $inst_regex
        AND ANY(constr IN b.constraints WHERE constr =~ $constr_regex)
        RETURN b.address as address, b.instructions as instructions
        """
        return self.neo4j.run(query, {
            'inst_regex': params.instructions_regex,
            'constr_regex': params.constraints_regex
        }).data()

    def _execute_dataflow(self, params: QueryParams) -> List[Dict[str, Any]]:
        """执行数据流追踪"""
        query = """
        MATCH path=(start:Block)-[:DATA_DEP*]->(end:Block)
        WHERE 
            length(path) <= $max_depth 
            AND ALL(r in relationships(path) WHERE r.var_info CONTAINS $var)
        RETURN 
            start.address as start_addr,
            end.address as end_addr,
            [n in nodes(path) | n.address] as path,
            [r in relationships(path) | r.var_info] as vars
        """
        return self.neo4j.run(query, {
            'var': params.var_name,
            'max_depth': params.max_depth
        }).data()

    def _execute_constrained_path(self, params: QueryParams) -> List[Dict[str, Any]]:
        """执行带约束的路径查询"""
        path_query = """
        MATCH path=(start:Block)-[:CONTROL_FLOW*]->(end:Block)
        WHERE start.address = $start AND end.address = $end
        RETURN [n in nodes(path) | n.address] as path
        """
        paths = self.neo4j.run(path_query, {
            'start': hex(params.start_addr),
            'end': hex(params.end_addr)
        }).data()

        valid_paths = []
        for record in paths:
            path_addrs = [self._parse_address(addr) for addr in record['path']]
            if self._symbolic_verify(path_addrs, params.constraints):
                valid_paths.append({
                    "path": path_addrs,
                    "constraints_satisfied": params.constraints
                })
        return valid_paths

    def _symbolic_verify(self, path_addrs: List[int], constraints: List[str]) -> bool:
        """符号执行验证（带缓存）"""
        cache_key = tuple(path_addrs + constraints)
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        if not self.proj:
            raise ValueError("需要angr项目实例进行符号执行")

        state = self.proj.factory.blank_state(addr=path_addrs[0])
        sm = self.proj.factory.simgr(state)

        try:
            for addr in path_addrs[1:]:
                sm.step()
                sm = sm.active
                valid = [s for s in sm if s.addr == addr]
                if not valid:
                    self._query_cache[cache_key] = False
                    return False
                sm = self.proj.factory.simgr(valid[0])

            for constr in constraints:
                state.solver.add(eval(constr, None, state.solver.__dict__))

            result = sm.one_active.solver.satisfiable()
            self._query_cache[cache_key] = result
            return result
        except Exception as e:
            logger.error(f"符号执行失败: {str(e)}")
            return False

    def _generate_visualization(self, params: QueryParams) -> str:
        """生成可视化图表（带缓存）"""
        cache_key = tuple(params.path_addrs)
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        nodes = self._get_nodes(params.path_addrs)
        edges = self._get_edges(params.path_addrs)

        # dot = f"digraph G {{\n{';\n'.join(nodes)};\n{';\n'.join(edges)}\n}}"
        dot_template = (
            "digraph G {{\n"  # 双花括号转义单个花括号
            "{nodes}\n"
            "{edges}\n"
            "}}"
        )

        return dot_template.format(
            nodes='\n'.join(nodes),
            edges='\n'.join(edges)
        )

    def _get_nodes(self, addrs: List[int]) -> List[str]:
        """获取节点描述"""
        return [f'"{hex(addr)}" [label="{self._get_instructions(addr)}"]'
                for addr in addrs]

    def _get_edges(self, addrs: List[int]) -> List[str]:
        """获取边描述"""
        query = """
        MATCH (a)-[r]->(b)
        WHERE a.address IN $addrs AND b.address IN $addrs
        RETURN a.address as src, r.type as type, b.address as dst
        """
        return [
            f'"{record["src"]}" -> "{record["dst"]}" [label="{record["type"]}"]'
            for record in self.neo4j.run(query, addrs=[hex(a) for a in addrs])
        ]

    def _get_instructions(self, addr: int) -> str:
        """获取指令文本（带缓存）"""
        if addr not in self._query_cache:
            node = self.matcher.match("Block", address=hex(addr)).first()
            self._query_cache[addr] = node["instructions"][:50] if node else "Unknown"
        return self._query_cache[addr]

    def _parse_address(self, addr) -> int:
        """地址解析统一处理"""
        if isinstance(addr, int):
            return addr
        try:
            return int(addr, 16) if isinstance(addr, str) else int(addr)
        except ValueError:
            raise InvalidParameterError(f"无效地址格式: {addr}")


# 使用示例
if __name__ == "__main__":

    # 初始化示例
    neo4j_graph = Graph("bolt://localhost:7687", auth=("neo4j", "neo4j123456")) # 传入实际数据库字符串
    angr_project = Project('/home/bank', auto_load_libs=False)  # 实际使用时应传入真实项目

    engine = SPDGQueryEngine(neo4j_graph, angr_project)

    # 1. stdin输入有效性检查
    params = QueryParams(
        query_type=QueryType.CYPHER,
        cypher_pattern="""
        MATCH (b:Block)
        WHERE ANY(constr IN b.constraints WHERE constr CONTAINS $pattern)
        RETURN b.address AS addr, b.instructions AS insns
        """,
        cypher_params={'pattern': 'packet_0_stdin_80_480[479:472] != 10'}
    )
    stdin_checks = engine.execute_query(params)
    print("1",stdin_checks)

    # 2. 查找涉及指针传递且包含输入验证的代码模式
    # params = QueryParams(
    #     query_type=QueryType.SEMANTIC,
    #     instructions_regex=r"mov\s+rdi,.*rax",  # 使用原始字符串
    #     constraints_regex=r"stdin_81_480.*!="
    # )
    # pointer_checks = engine.execute_query(params)
    # 查找涉及指针传递且包含输入验证的代码模式
    params = QueryParams(
        query_type=QueryType.SEMANTIC,
        instructions_regex=r"(lea\s+\w+,\s*$$\w+\s*\+\s*\w*\s*$$;\s*mov\s+\w+,\s*\w+)|(mov\s+\w+,\s*\w+\s*;\s*call)|(mov\s+rdi,\s*rax)",
        constraints_regex=r"stdin_.*(!=|=)"
    )

    pointer_checks = engine.execute_query(params)
    print("2", pointer_checks)

    # 3. 换行符检查
    params = QueryParams(
        query_type=QueryType.CYPHER,
        cypher_pattern=r"""
        MATCH (b:Block)
        WHERE ANY(constr IN b.constraints 
            WHERE constr CONTAINS '[479:472]'
            AND (constr CONTAINS '!= 10' OR constr CONTAINS '!= 0xA'))
        RETURN 
            b.address AS address,
            [c IN b.constraints WHERE c CONTAINS '[479:472]'] AS constraints,
            b.instructions AS instructions
        LIMIT 20
        """
    )
    newline_checks = engine.execute_query(params)
    print("3", newline_checks)

    # 4. 多重空白检查
    params = QueryParams(
        query_type=QueryType.CYPHER,
        cypher_pattern="""
        MATCH (b:Block)
        WHERE SIZE([c IN b.constraints WHERE 
            c CONTAINS $c1 OR 
            c CONTAINS $c2 OR
            c CONTAINS $c3 OR
            c CONTAINS $c4]) >= $min_count
        RETURN b.address AS addr
        """,
        cypher_params={
            'c1': '!= 9>',
            'c2': '!= 10>',
            'c3': '!= 11>',
            'c4': '!= 13>',
            'min_count': 3
        }
    )
    whitespace_checks = engine.execute_query(params)
    print("4", whitespace_checks)


    # 5. 数据流追踪
    params = QueryParams(
        query_type=QueryType.DATAFLOW,
        var_name="rbp<8>"
        #,max_depth=5
    )
    taint_paths = engine.execute_query(params)
    print("5", taint_paths)

    # 6. 约束路径验证
    params = QueryParams(
        query_type=QueryType.CONSTRAINED_PATH,
        start_addr=0x4011a9,
        end_addr=0x401352,
        constraints=[
            "state.solver.BVS('stdin_81_480', 8) == 65",
            "state.solver.BVS('stdin_81_480', 8) == 66"
        ]
    )
    valid_paths = engine.execute_query(params)
    print("6", valid_paths)

    # 7. 函数调用准备模式
    params = QueryParams(
        query_type=QueryType.CYPHER,
        cypher_pattern="""
        MATCH (b:Block)
        WHERE b.instructions =~ $insn_regex
        RETURN b.address AS call_site
        """,
        cypher_params={'insn_regex': r'.*lea rax,.*; mov rdi, rax; call.*'}
    )
    call_preps = engine.execute_query(params)
    print("7", call_preps)

    # 8. 矛盾约束检查
    params = QueryParams(
        query_type=QueryType.CYPHER,
        cypher_pattern="""
        MATCH (b:Block)
        WHERE ANY(c1 IN b.constraints WHERE c1 CONTAINS $c1) 
        AND ANY(c2 IN b.constraints WHERE c2 CONTAINS $c2)
        RETURN b.address AS conflict_block
        """,
        cypher_params={
            'c1': '!= 9>',
            'c2': '== 9>'
        }
    )
    constraint_conflicts = engine.execute_query(params)
    print("8", constraint_conflicts)


