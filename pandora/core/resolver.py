"""
模块解析器 (module_resolver.py)
==============================
将 Record → Literal Array → REGULAR_IMPORT 三者关联,
为每个函数建立 local_name → module_request 的映射。
"""

from .parser import PaFile, PaFunction, PaRecord, ModuleLiteralArray


class ModuleResolver:
    """
    解析每个函数所属模块的导入映射。

    核心逻辑:
      1. 从函数全限定名推导所属 Record
      2. 从 Record 的 moduleRecordIdx 找到对应 Literal Array
      3. 从 Literal Array 的 REGULAR_IMPORT 构建 local_name → module_request 映射
    """

    def __init__(self, pa: PaFile):
        self.pa = pa
        # 缓存: record_name -> {local_name: module_request}
        self._import_cache: dict[str, dict[str, str]] = {}
        self._build_cache()

    def _build_cache(self):
        """预构建所有 Record 的导入映射"""
        for rec in self.pa.records:
            if not rec.module_record_idx:
                continue

            lit = self.pa.hex_to_literal.get(rec.module_record_idx)
            if lit is None:
                continue

            import_map = {}
            for imp in lit.regular_imports:
                import_map[imp.local_name] = imp.module_request
            self._import_cache[rec.name] = import_map

    def resolve_function_record(self, func: PaFunction) -> PaRecord | None:
        """
        从函数全限定名找到所属 Record。
        函数名格式: com.xxx.pages.Clipboard.aboutToAppear
        Record名格式: com.xxx.pages.Clipboard
        策略: 最长前缀匹配
        """
        best_match = None
        best_len = 0
        for rec_name in self.pa.record_by_name:
            if func.name.startswith(rec_name) and len(rec_name) > best_len:
                best_match = self.pa.record_by_name[rec_name]
                best_len = len(rec_name)
        return best_match

    def get_import_map(self, func: PaFunction) -> dict[str, str]:
        """
        获取函数所属模块的导入映射。
        返回 {local_name: module_request}, e.g. {"pasteboard": "@ohos:pasteboard"}
        """
        rec = self.resolve_function_record(func)
        if rec is None:
            return {}
        return self._import_cache.get(rec.name, {})

    def resolve_local_name(self, func: PaFunction, local_name: str) -> str | None:
        """将 throw.undefinedifholewithname 的 local_name 解析为 module_request"""
        import_map = self.get_import_map(func)
        return import_map.get(local_name)
