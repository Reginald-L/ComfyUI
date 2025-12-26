# 备注
## git clone组件后在提交前自动注册为submodule
在.git/hooks中新建pre-commit文件, 没有任何后缀, 将以下代码写入
```python
#!/usr/bin/env python3
import os
import subprocess
import sys

# 配置路径
NODES_DIR = "custom_nodes"

def get_staged_changes():
    """获取暂存区的文件列表"""
    result = subprocess.run(["git", "diff", "--cached", "--name-only"], capture_output=True, text=True)
    return result.stdout.splitlines()

def is_submodule(path):
    """检查路径是否已经是 submodule"""
    # 通过 git submodule status 检查
    result = subprocess.run(["git", "submodule", "status", path], capture_output=True, text=True)
    return result.returncode == 0

def convert_to_submodule(path):
    """尝试将普通 git 目录转换为 submodule"""
    print(f"[Auto-Hook] 检测到未注册的 Git 仓库: {path}")
    
    # 1. 获取远程 URL
    try:
        url = subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=path, text=True).strip()
    except:
        print(f"  [Error] 无法获取远程 URL，跳过: {path}")
        return False

    print(f"  -> 正在自动注册 Submodule: {url}")
    
    # 2. 这里有个 tricky 的地方：git submodule add 不允许目标目录已存在
    # 所以我们需要：先从 git 索引移除（如果被误add），重命名备份，add submodule，再恢复内容(git会自动checkout)
    
    # 简单粗暴做法：直接由用户确认，或者帮用户执行 git submodule add --force
    # 由于是 pre-commit，自动修改文件结构比较危险，我们选择自动修改 .gitmodules
    
    try:
        # 这一步是为了防止你已经把那个文件夹作为普通文件 add 进去了
        subprocess.run(["git", "rm", "--cached", "-r", path], stderr=subprocess.DEVNULL, check=False)
        
        # 强制添加 submodule
        subprocess.run(["git", "submodule", "add", "--force", url, path], check=True)
        
        # 自动把新生成的 .gitmodules 和文件夹加入本次 commit
        subprocess.run(["git", "add", ".gitmodules", path], check=True)
        print(f"  [Success] 已成功注册为 submodule!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [Fail] 自动注册失败，请手动处理。Error: {e}")
        return False

def main():
    if not os.path.exists(NODES_DIR):
        return 0

    # 遍历 custom_nodes 目录
    for item in os.listdir(NODES_DIR):
        item_path = os.path.join(NODES_DIR, item)
        
        # 如果是一个目录，且里面有 .git 文件夹 (说明是 git clone 下来的)
        if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, ".git")):
            # 检查它是否已经是 submodule
            if not is_submodule(item_path):
                # 这是一个“野生”的 git 仓库，执行自动转化
                convert_to_submodule(item_path)

if __name__ == "__main__":
    main()
```
赋予执行权限
```bash
chmod +x .git/hooks/pre-commit
```
