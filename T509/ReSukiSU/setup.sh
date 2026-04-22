#!/bin/sh

# Repo Clone
curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/refs/heads/main/kernel/setup.sh" | bash -

# pacth scripts
wget https://raw.githubusercontent.com/JackA1ltman/NonGKI_Kernel_Build_2nd/refs/heads/mainline/Patches/Patch/susfs_patch_to_4.14.patch
wget https://raw.githubusercontent.com/JackA1ltman/NonGKI_Kernel_Build_2nd/refs/heads/mainline/Patches/susfs_inline_hook_patches.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports/patch_internal_h.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports/patch_maccess.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports/patch_namespace.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports/patch_uaccess_h.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports_selinux/patch_objsec_h.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports_selinux/patch_selinux_xfrm.sh
wget https://raw.githubusercontent.com/DevCat3/DevCatowa_Random_stuff/refs/heads/main/T509/backports_selinux/patch_selinuxfs.sh

# Configs
echo "
# KernelSU
CONFIG_KSU=y
CONFIG_KSU_SUSFS=y
CONFIG_KSU_SUSFS_SUS_PATH=y
CONFIG_KSU_SUSFS_SUS_MOUNT=y
CONFIG_KSU_SUSFS_SUS_KSTAT=y
CONFIG_KSU_SUSFS_SPOOF_UNAME=y
CONFIG_KSU_SUSFS_ENABLE_LOG=y
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y
CONFIG_KSU_SUSFS_OPEN_REDIRECT=y
CONFIG_KSU_SUSFS_SUS_MAP=y
" >> arch/arm64/configs/gta4lve_eur_open_defconfig


# Setting permissions
chmod +xrw susfs_patch_to_4.14.patch
chmod +xrw susfs_inline_hook_patches.sh
chmod +xrw patch_uaccess_h.sh
chmod +xrw patch_namespace.sh
chmod +xrw patch_maccess.sh
chmod +xrw patch_internal_h.sh
chmod +xrw patch_objsec_h.sh
chmod +xrw patch_selinux_xfrm.sh
chmod +xrw patch_selinuxfs.sh

# Applying patches
patch -p1 < susfs_patch_to_4.14.patch
bash susfs_inline_hook_patches.sh
bash patch_internal_h.sh
bash patch_maccess.sh
bash patch_namespace.sh
bash patch_uaccess_h.sh
bash patch_objsec_h.sh
bash patch_selinuxfs.sh
bash patch_selinux_xfrm.sh

# Solving rejections
sed -i 's/CONFIG_LOCALVERSION=""/CONFIG_LOCALVERSION="-CuteCat"/' arch/arm64/configs/gta4lve_eur_open_defconfig
sed -i '/#include "internal.h"/i #if defined(CONFIG_KSU_SUSFS_SUS_PATH) || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)\n#include <linux\/susfs_def.h>\n#endif' fs/namei.c
sed -i '/#include "pnode.h"/i #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n#include <linux/susfs_def.h>\n#endif \/\/ #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT' fs/namespace.c
sed -i '/#include "internal.h"/a #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\nextern bool susfs_is_current_ksu_domain(void);\nextern bool susfs_is_sdcard_android_data_decrypted;\n\n#define CL_COPY_MNT_NS BIT(25) /* used by copy_mnt_ns() */\n\nstatic DEFINE_IDA(susfs_mnt_id_ida);\nstatic DEFINE_IDA(susfs_mnt_group_ida);\n\n#endif \/\/ #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT' fs/namespace.c
sed -i '/u32 mask = mark->mask & IN_ALL_EVENTS;/ {
h
r /dev/stdin
g
N
}' fs/notify/fdinfo.c << 'EOF'
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
               mnt = real_mount(file->f_path.mnt);
               if (mnt->mnt_id >= DEFAULT_KSU_MNT_ID &&
                       likely(susfs_is_current_proc_umounted()))
               {
                       struct path path;
                       char *pathname = kmalloc(PAGE_SIZE, GFP_KERNEL);
                       char *dpath;
                       if (!pathname) {
                               goto orig_flow;
                       }
                       dpath = d_path(&file->f_path, pathname, PAGE_SIZE);
                       if (!dpath) {
                               goto out_kfree;
                       }
                       if (kern_path(dpath, 0, &path)) {
                               goto out_kfree;
                       }
                       if (!path.dentry->d_inode) {
                               goto out_path_put;
                       }
                       seq_printf(m, "inotify wd:%x ino:%lx sdev:%x mask:%x ignored_mask:0 ",
                          inode_mark->wd, path.dentry->d_inode->i_ino, path.dentry->d_inode->i_sb->s_dev,
                          inotify_mark_user_mask(mark));
                       show_mark_fhandle(m, path.dentry->d_inode);
                       seq_putc(m, '\n');
                       path_put(&path);
                       kfree(pathname);
                       iput(inode);
                       return;

out_path_put:
                       path_put(&path);
out_kfree:
                       kfree(pathname);
               }
orig_flow:
#endif
EOF

sed -i '/this_len = access_remote_vm(mm, addr, page, this_len, flags);/ {
r /dev/stdin
}' fs/proc/base.c << 'EOF'
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
               vma = find_vma(mm, addr);
               if (vma && vma->vm_file) {
                       struct inode *inode = file_inode(vma->vm_file);
                       if (inode->i_mapping &&
                               unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags) &&
                               susfs_is_current_proc_umounted_app()))
                       {
                               if (write) {
                                       copied = -EFAULT;
                               } else {
                                       copied = -EIO;
                               }
                               *ppos = addr;
                               mmput(mm);
                               goto free;
                       }
               }
#endif
EOF

python3 << 'EOF'
lines = open('fs/proc/task_mmu.c').readlines()
new_code = '#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n'
new_code += '       if (vma->vm_file) {\n'
new_code += '               struct inode *inode = file_inode(vma->vm_file);\n'
new_code += '               if (inode->i_mapping &&\n'
new_code += '                       unlikely(test_bit(AS_FLAGS_SUS_MAP, &inode->i_mapping->flags) &&\n'
new_code += '                       susfs_is_current_proc_umounted_app()))\n'
new_code += '               {\n'
new_code += '                       seq_puts(m, "VmFlags: mr mw me");\n'
new_code += "                       seq_putc(m, '\\n');\n"
new_code += '                       goto bypass_orig_flow2;\n'
new_code += '               }\n'
new_code += '       }\n'
new_code += '#endif\n'
target = 'arch_show_smap(m, vma);'
idx = next(i for i, l in enumerate(lines) if target in l)
lines.insert(idx, new_code)
open('fs/proc/task_mmu.c', 'w').writelines(lines)
print("Done!")
EOF

python3 << 'EOF'
lines = open('fs/proc/task_mmu.c').readlines()
new_code = '#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n'
new_code += 'bypass_orig_flow2:\n'
new_code += '#endif\n'
lines.insert(1149, new_code)
open('fs/proc/task_mmu.c', 'w').writelines(lines)
print("Done!")
EOF

python3 << 'EOF'
lines = open('fs/readdir.c').readlines()
new_code = '#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n'
new_code += '       struct inode *inode;\n'
new_code += '#endif\n'
lines.insert(551, new_code)
open('fs/readdir.c', 'w').writelines(lines)
print("Done!")
EOF

sed -i 's/static int mnt_alloc_id(struct mount \*mnt)/static int __maybe_unused mnt_alloc_id(struct mount *mnt)/' fs/namespace.c
