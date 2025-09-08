# coding=utf-8
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaClass, IJavaMethod, IJavaField
import re
import os

class JEB5RenameScript(IScript):
    def run(self, ctx):
        try:
            # 获取当前 JEB 项目
            prj = ctx.getProject()
            if not prj:
                print('Error: No project loaded in JEB')
                return

            # 规则文件路径（可根据需要修改）
            rules_file = r'D:\desktop\wgsdk\2\rename.txt'
            if not os.path.exists(rules_file):
                print('Error: Rules file "{}" not found'.format(rules_file))
                return

            # 解析规则文件
            rename_rules = self.parse_rules(rules_file)
            if not rename_rules:
                print('Error: No valid rules found in the file')
                return

            # 获取所有 Java 源单元
            units = RuntimeProjectUtil.findUnitsByType(prj, IJavaSourceUnit, False)
            if not units:
                print('Error: No Java source units found in the project')
                return

            # 遍历规则并应用重命名
            for rule in rename_rules:
                self.apply_rule(units, rule)
        except Exception as e:
            print('Renaming completed. Check the log for details.')

    def parse_rules(self, rules_file):
        """解析改名规则文件，返回规则列表"""
        rules = []
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('//'):
                        continue
                    # 使用正则表达式解析规则
                    match = re.match(r'^(.*?)\.(.*?):(.*?)->(.*?)\.(.*?):(.*?)//(.*)$', line)
                    if match:
                        orig_pkg, orig_cls, orig_sym, new_pkg, new_cls, new_sym, comment = match.groups()
                        rules.append({
                            'orig_package': orig_pkg,
                            'orig_class': orig_cls,
                            'orig_symbol': orig_sym,
                            'new_package': new_pkg,
                            'new_class': new_cls,
                            'new_symbol': new_sym,
                            'comment': comment
                        })
                    else:
                        print('Warning: Invalid rule format: {}'.format(line))
        except Exception as e:
            print('Error reading rules file: {}'.format(e))
        return rules

    def apply_rule(self, units, rule):
        """应用单个重命名规则"""
        orig_pkg = rule['orig_package']
        orig_cls = rule['orig_class']
        orig_sym = rule['orig_symbol']
        new_pkg = rule['new_package']
        new_cls = rule['new_class']
        new_sym = rule['new_symbol']

        # 构建原始类全限定名
        orig_class_fqn = '{}.{}'.format(orig_pkg.replace('.', '/'), orig_cls)

        # 查找匹配的类
        target_class = None
        for unit in units:
            for cls in unit.getClasses():
                if cls.getSignature().replace('/', '.').startswith(orig_pkg + '.' + orig_cls):
                    target_class = cls
                    break
            if target_class:
                break

        if not target_class:
            print('Class not found: {}'.format(orig_class_fqn))
            return

        # 如果新类名不同，尝试重命名类
        if orig_cls != new_cls:
            new_class_fqn = '{}.{}'.format(new_pkg.replace('.', '/'), new_cls)
            try:
                target_class.setName(new_cls)
                print('Renamed class: {} -> {}'.format(orig_class_fqn, new_class_fqn))
            except Exception as e:
                print('Error renaming class {}: {}'.format(orig_class_fqn, e))
                return

        # 检查是方法还是字段
        found = False
        # 查找方法
        for method in target_class.getMethods():
            if method.getName() == orig_sym:
                try:
                    method.setName(new_sym)
                    print('Renamed method: {}.{} -> {}.{}'.format(orig_class_fqn, orig_sym, new_class_fqn, new_sym))
                    found = True
                    break
                except Exception as e:
                    print('Error renaming method {}.{}: {}'.format(orig_class_fqn, orig_sym, e))

        # 查找字段
        if not found:
            for field in target_class.getFields():
                if field.getName() == orig_sym:
                    try:
                        field.setName(new_sym)
                        print('Renamed field: {}.{} -> {}.{}'.format(orig_class_fqn, orig_sym, new_class_fqn, new_sym))
                        found = True
                        break
                    except Exception as e:
                        print('Error renaming field {}.{}: {}'.format(orig_class_fqn, orig_sym, e))

        if not found:
            print('Symbol not found: {}.{}'.format(orig_class_fqn, orig_sym))

if __name__ == "__main__":
    print('JEB5 Rename Script: Starting...')