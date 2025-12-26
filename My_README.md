# 备注

## 如何使用
```bash
git clone --recursive <git repo link>
```
如果已经克隆项目,但是忘记拉取submodules, 执行以下指令
```bash
git submodule update --init --recursive
```
Note: `git pull` 只会拉取主项目文件, 不会自动更新submodules中的内容, 如果想要一起更新, 执行
```bash
# 拉取主项目更新，同时更新所有子模块到主项目记录的那个版本
git pull --recurse-submodules

# 手动更新所有子模块
git submodule update --remote --merge
```

## git clone组件后在提交前自动注册为submodule
在.git/hooks中新建pre-commit文件, 没有任何后缀, 将以下代码写入

```
# 1. 覆盖写入 Shell 脚本版本的 pre-commit 钩子
cat << 'EOF' > .git/hooks/pre-commit
#!/bin/sh

# 设置 custom_nodes 路径
NODES_DIR="custom_nodes"

# 检查目录是否存在
if [ ! -d "$NODES_DIR" ]; then
    exit 0
fi

# 遍历 custom_nodes 下的所有目录
for dir in "$NODES_DIR"/*; do
    # 只有当它是目录，且内部包含 .git 文件夹时才处理
    if [ -d "$dir" ] && [ -d "$dir/.git" ]; then
        
        # 检查是否已经是 submodule (git submodule status 返回非 0 表示不是 submodule)
        git submodule status "$dir" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "[Auto-Hook] 发现未注册的仓库: $dir"
            
            # 获取远程 URL
            url=$(git -C "$dir" remote get-url origin)
            
            if [ -z "$url" ]; then
                echo "  [Error] 无法获取远程 URL，跳过。"
                continue
            fi
            
            echo "  -> 正在注册 Submodule: $url"
            
            # 1. 防止已经被错误地 add 到了暂存区，先移除索引
            git rm --cached -r "$dir" > /dev/null 2>&1
            
            # 2. 强制添加为 submodule
            git submodule add --force "$url" "$dir"
            
            # 3. 如果成功，将 .gitmodules 和新目录加入本次 commit
            if [ $? -eq 0 ]; then
                git add .gitmodules "$dir"
                echo "  [Success] 注册成功！"
            else
                echo "  [Fail] 注册失败，请检查。"
                exit 1
            fi
        fi
    fi
done

exit 0
EOF

# 2. 赋予执行权限
chmod +x .git/hooks/pre-commit
```

