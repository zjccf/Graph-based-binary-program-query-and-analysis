import angr
import logging
from networkx import DiGraph
from py2neo import Graph, Node, Relationship, NodeMatcher
from typing import Optional, Dict, Any


class SPDGConfiguration:
    """SPDG 分析全局配置类"""

    def __init__(
            self,
            # 基础分析参数
            binary_path: str,
            # CFG 配置
            cfg_type: str = "emulated",  # "fast" 或 "emulated"
            cfg_options: Optional[Dict[str, Any]] = None,
            # 数据依赖分析配置
            data_dep_enabled: bool = True,
            data_dep_options: Optional[Dict[str, Any]] = None,
            # 符号执行配置
            symbolic_enabled: bool = True,
            symbolic_options: Optional[Dict[str, Any]] = None,
            # Neo4j 配置
            neo4j_enabled: bool = True,
            neo4j_options: Optional[Dict[str, Any]] = None,
            # 日志配置
            log_level: int = logging.INFO,
    ):
        # 基础参数
        self.binary_path = binary_path

        # CFG 配置
        self.cfg_type = cfg_type
        self.cfg_options = cfg_options or {
            'context_sensitivity_level': 2, #范围1-3
            'resolve_indirect_jumps': True,
            'cross_references': True,
            'collect_data_refs': True,
            'normalize': True
        }

        # 数据依赖配置
        self.data_dep_enabled = data_dep_enabled
        self.data_dep_options = data_dep_options or {
            'track_tmps': True,
            'track_memory': True,
            'def_use_threshold': None,
            'cross_function': True
        }

        # 符号执行配置
        self.symbolic_enabled = symbolic_enabled
        self.symbolic_options = symbolic_options or {
            'max_steps': 100,
            'timeout': None,
            'avoid_loops': True,
            'concretize_memory': False,
            'symbolic_memory': True
        }

        # Neo4j 配置
        self.neo4j_enabled = neo4j_enabled
        self.neo4j_options = neo4j_options or {
            'uri': "bolt://localhost:7687",
            'auth': ("neo4j", "neo4j123456"),
            'batch_size': 1000,
            'sync_nodes': True,
            'sync_edges': True,
            'sync_constraints': True
        }

        # 日志配置
        self.log_level = log_level


class SPDGBuilder:
    def __init__(self, config: SPDGConfiguration):
        # 初始化配置
        self.cfg = config
        self._validate_config()

        # 初始化日志
        logging.basicConfig(level=self.cfg.log_level)
        self.logger = logging.getLogger(__name__)

        # 初始化Angr项目
        self.proj = angr.Project(
            self.cfg.binary_path,
            auto_load_libs=False,
            load_options={'auto_load_libs': False}
        )

        # 构建CFG
        self._build_cfg()

        # 初始化数据结构
        self.spdg = DiGraph()
        self._init_neo4j()

    def _validate_config(self):
        """验证配置有效性"""
        if self.cfg.cfg_type not in ['fast', 'emulated']:
            raise ValueError("Invalid CFG type, must be 'fast' or 'emulated'")

        if self.cfg.neo4j_enabled and not self.cfg.neo4j_options.get('uri'):
            raise ValueError("Neo4j URI is required when Neo4j is enabled")

    def _build_cfg(self):
        """根据配置构建控制流图"""
        cfg_builder = {
            'fast': self.proj.analyses.CFGFast,
            'emulated': self.proj.analyses.CFGEmulated
        }[self.cfg.cfg_type]

        self.cfg_obj = cfg_builder(**self.cfg.cfg_options)
        self.logger.info(f"Built {self.cfg.cfg_type} CFG with options: {self.cfg.cfg_options}")

    def _init_neo4j(self):
        """初始化Neo4j连接"""
        if self.cfg.neo4j_enabled:
            self.neo4j = Graph(
                self.cfg.neo4j_options['uri'],
                auth=self.cfg.neo4j_options['auth']
            )
            self.neo4j_batch = []
            self.match = NodeMatcher(self.neo4j)
            self.logger.info("Neo4j connection initialized")
        else:
            self.neo4j = None

    def build_spdg(self) -> DiGraph:
        """主构建流程"""
        self._build_control_flow()

        if self.cfg.data_dep_enabled:
            self._build_data_dependencies()

        if self.cfg.symbolic_enabled:
            self._perform_symbolic_execution()

        self._flush_neo4j_batch()
        return self.spdg

    def _build_control_flow(self):
        """构建控制流结构"""
        self.logger.debug("Building control flow...")

        # 添加基本块节点
        for func in self.cfg_obj.functions:
            for block in self.cfg_obj.functions.function(addr=func).blocks:
                self._add_block_node(block,func)

        # 添加控制流边
        self._add_cfg_edges()

    def _add_block_node(self, block,func):
        """添加基本块节点到SPDG和Neo4j"""
        # SPDG节点
        node_attrs = {
            'type': 'Block',
            'addr': block.addr,
            'instructions': [f"{insn.mnemonic} {insn.op_str}" for insn in block.disassembly.insns],
            'size': block.size,
            'function': func if func else None
        }
        # print(node_attrs['instructions'])
        self.spdg.add_node(block.addr, **node_attrs)

        # Neo4j同步
        if self.cfg.neo4j_enabled and self.cfg.neo4j_options['sync_nodes']:
            neo_node = Node(
                "Block",
                address=hex(block.addr),
                instructions="; ".join(node_attrs['instructions']),
                size=block.size,
                function_addr=hex(node_attrs['function']) if node_attrs['function'] else None
            )
            # print(neo_node.instructions)
            self._neo4j_batch_upsert(neo_node)

    def _add_cfg_edges(self):
        """添加控制流边"""
        for func in self.cfg_obj.functions:
            cfg_graph = self.cfg_obj.functions.function(addr=func).graph
            for src, dst in cfg_graph.edges():
                self.spdg.add_edge(src.addr, dst.addr, type='control_flow')

                if self.cfg.neo4j_enabled and self.cfg.neo4j_options['sync_edges']:
                    self._add_neo4j_relationship(
                        src.addr,
                        dst.addr,
                        "CONTROL_FLOW"
                    )

    def _build_data_dependencies(self):
        """构建数据依赖关系"""
        self.logger.debug("Building data dependencies...")

        for func in self.cfg_obj.functions.values():
            rd = self.proj.analyses.ReachingDefinitions(
                subject=func,
                func_graph=func.graph,
                **self.cfg.data_dep_options
            )

            for def_ in rd.all_definitions:
                if self.cfg.data_dep_options.get('def_use_threshold'):
                    if def_.count > self.cfg.data_dep_options['def_use_threshold']:
                        continue

                for use in rd.all_uses.get_uses(def_):
                    if def_.codeloc.block_addr == use.block_addr:
                        continue

                    self._add_data_dependency_edge(def_, use)

    def _add_data_dependency_edge(self, def_, use):
        """添加数据依赖边"""
        self.spdg.add_edge(
            def_.codeloc.block_addr,
            use.block_addr,
            type='data_dep',
            var_type=str(def_.atom.__class__.__name__),
            var_info=str(def_.atom)
            #,def_count=def_.count
        )

        if self.cfg.neo4j_enabled and self.cfg.neo4j_options['sync_edges']:
            self._add_neo4j_relationship(
                def_.codeloc.block_addr,
                use.block_addr,
                "DATA_DEP",
                {
                    'identifier': f"{hex(def_.codeloc.block_addr)}_{hex(use.block_addr)}_DATA_DEP",
                    'var_type': str(def_.atom.__class__.__name__),
                    'var_info': str(def_.atom)
                    #,'def_count': def_.count
                }
            )

    def _perform_symbolic_execution(self):
        """执行符号执行分析"""
        self.logger.debug("Performing symbolic execution...")

        main_func = self.cfg_obj.functions.get('main', None)
        if not main_func:
            self.logger.warning("No main function found, skipping symbolic execution")
            return

        entry_state = self.proj.factory.entry_state(
            addr=main_func.addr,
            add_options={
                angr.options.SYMBOLIC_WRITE_ADDRESSES
                # if self.cfg.symbolic_options['symbolic_memory']
                # else angr.options.CONCRETIZE_WRITE_STRINGS
            }
        )

        simgr = self.proj.factory.simgr(entry_state)
        simgr.run(
            n=self.cfg.symbolic_options['max_steps'],
            timeout=self.cfg.symbolic_options['timeout']
        )

        for path in simgr.deadended:
            self._process_symbolic_path(path)

    def _process_symbolic_path(self, path):
        """处理符号执行路径"""
        for block_addr in path.history.bbl_addrs:
            constraints = [str(c) for c in path.solver.constraints]

            if block_addr in self.spdg.nodes:
                self.spdg.nodes[block_addr]['constraints'] = constraints

                if self.cfg.neo4j_enabled and self.cfg.neo4j_options['sync_constraints']:
                    self._update_neo4j_constraints(block_addr, constraints)

    def _neo4j_batch_upsert(self, node):
        """批量处理Neo4j更新"""
        self.neo4j_batch.append(node)
        if len(self.neo4j_batch) >= self.cfg.neo4j_options.get('batch_size', 1000):
            self._flush_neo4j_batch()

    def _flush_neo4j_batch(self):
        """执行批量写入"""
        if self.neo4j and self.neo4j_batch:
            tx = self.neo4j.begin()
            for item in self.neo4j_batch:
                tx.merge(item, "Block", "address")
            tx.commit()
            self.neo4j_batch.clear()
            self.logger.debug(f"Flushed {len(self.neo4j_batch)} Neo4j operations")

    # def _add_neo4j_relationship(self, src_addr, dst_addr, rel_type, props=None):
    #     """添加Neo4j关系"""
    #     src_node = Node("Block", address=hex(src_addr))
    #     dst_node = Node("Block", address=hex(dst_addr))
    #     rel = Relationship(src_node, rel_type, dst_node, **(props or {}))
    #     self.neo4j.merge(rel, rel_type )# "identifier"
    def _add_neo4j_relationship(self, src_addr, dst_addr, rel_type, props=None):
        """添加Neo4j关系"""
        # 创建节点对象（必须包含唯一标识属性）
        src_node = Node("Block", address=hex(src_addr))
        dst_node = Node("Block", address=hex(dst_addr))

        # 先合并节点（确保节点存在）
        self.neo4j.merge(src_node, "Block", "address")
        self.neo4j.merge(dst_node, "Block", "address")

        # 生成关系唯一标识
        identifier = f"{hex(src_addr)}_{hex(dst_addr)}_{rel_type}"

        # 创建关系对象（必须包含identifier）
        rel_props = {'identifier': identifier, ** (props or {})}
        rel = Relationship(src_node, rel_type, dst_node, ** rel_props)

        # 合并关系（使用identifier作为主键）
        self.neo4j.merge(rel, rel_type, "identifier")

    def _update_neo4j_constraints(self, block_addr, constraints):
        """更新Neo4j约束条件"""
        if self.cfg.neo4j_enabled:
            block_node = self.match.match("Block", address=hex(block_addr)).first()
            if block_node:
                block_node["constraints"] = constraints
                self.neo4j.push(block_node)


# 使用示例
if __name__ == "__main__":
    config = SPDGConfiguration(
        binary_path="/home/bank",
        cfg_type="emulated",
        symbolic_enabled=True,
        data_dep_enabled=True,
        cfg_options={
            'context_sensitivity_level': 1,
            'resolve_indirect_jumps': True
        },
        data_dep_options={
            'track_tmps': False
            # 'def_use_threshold': 500
        },
        symbolic_options={
            'max_steps': 100,
            'timeout': None,
            'symbolic_memory': False,

        },
        neo4j_options={
            'uri': "bolt://localhost:7687",
            'auth': ("neo4j", "neo4j123456"),
            'batch_size': 5000,
            'sync_nodes': True,
            'sync_edges': True,
            'sync_constraints': True
        },
        log_level=logging.DEBUG
    )

    builder = SPDGBuilder(config)
    spdg_graph = builder.build_spdg()
    print(f"Generated SPDG with {len(spdg_graph.nodes)} nodes and {len(spdg_graph.edges)} edges")
