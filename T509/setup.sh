#!/bin/sh

# Repo Clone
curl -LSs "https://raw.githubusercontent.com/rsuntk/KernelSU/main/kernel/setup.sh" | bash -s susfs-rksu-master
# curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash

# pacth scripts
wget https://raw.githubusercontent.com/rksuorg/kernel_patches/refs/heads/master/manual_hook/kernel-4.14.patch
wget https://raw.githubusercontent.com/JackA1ltman/NonGKI_Kernel_Build_2nd/refs/heads/mainline/Patches/Patch/susfs_patch_to_4.14.patch
wget https://raw.githubusercontent.com/JackA1ltman/NonGKI_Kernel_Build_2nd/refs/heads/mainline/Patches/susfs_inline_hook_patches.sh
wget https://raw.githubusercontent.com/JackA1ltman/NonGKI_Kernel_Build_2nd/refs/heads/mainline/Patches/backport_selinux_patches.sh
wget https://raw.githubusercontent.com/JackA1ltman/NonGKI_Kernel_Build_2nd/refs/heads/mainline/Patches/backport_patches.sh
wget https://raw.githubusercontent.com/DevCatowa/DevCatowa_Random_stuff/refs/heads/main/T509/setuid_hook.c
wget https://raw.githubusercontent.com/DevCatowa/DevCatowa_Random_stuff/refs/heads/main/T509/readdir.c
wget https://raw.githubusercontent.com/DevCatowa/DevCatowa_Random_stuff/refs/heads/main/T509/fdinfo.c
wget https://raw.githubusercontent.com/DevCatowa/DevCatowa_Random_stuff/refs/heads/main/T509/supercalls.c

# Configs
echo "
# KernelSU
CONFIG_KSU=y
CONFIG_KSU_SUSFS=y
CONFIG_KSU_SUSFS_SUS_PATH=y
CONFIG_KSU_SUSFS_SUS_MOUNT=y
CONFIG_KSU_SUSFS_SUS_KSTAT=y
CONFIG_KSU_SUSFS_TRY_UMOUNT=y
CONFIG_KSU_SUSFS_SPOOF_UNAME=y
CONFIG_KSU_SUSFS_ENABLE_LOG=y
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y
CONFIG_KSU_SUSFS_OPEN_REDIRECT=y
CONFIG_KSU_SUSFS_SUS_MAP=y
CONFIG_KSU_MULTI_MANAGER_SUPPORT=y
CONFIG_CPU_FREQ_GOV_POWERSAVE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y
CONFIG_CPU_FREQ_GOV_INTERACTIVE=y
" >> arch/arm64/configs/gta4lve_eur_open_defconfig


# Setting permissions
chmod +xrw kernel-4.14.patch
chmod +xrw susfs_patch_to_4.14.patch
chmod +xrw susfs_inline_hook_patches.sh
chmod +xrw backport_selinux_patches.sh
chmod +xrw backport_patches.sh
chmod +xrw fdinfo.c
chmod +xrw readdir.c
chmod +xrw setuid_hook.c
chmod +xrw supercalls.c

# Applying patches
# patch -p1 < kernel-4.14.patch
patch -p1 < susfs_patch_to_4.14.patch
# bash backport_patches.sh
# bash backport_selinux_patches.sh
bash susfs_inline_hook_patches.sh

# Solving rejections
sed -i 's/CONFIG_LOCALVERSION=""/CONFIG_LOCALVERSION="-BlackCat"/' arch/arm64/configs/gta4lve_eur_open_defconfig
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

# backport for TRY_UMOUNT
python3 << 'EOF'
lines = open('include/linux/susfs_def.h').readlines()
new_code = '#define DEFAULT_SUS_MNT_ID_FOR_KSU_PROC_UNSHARE 1000000 /* used by vfsmount->susfs_mnt_id_backup */\n'
target = '#define DEFAULT_KSU_MNT_GROUP_ID 5000 /* used by mount->mnt_group_id */'
idx = next(i for i, l in enumerate(lines) if target in l)
lines.insert(idx, new_code)
open('include/linux/susfs_def.h', 'w').writelines(lines)
print("Done!")
EOF

python3 << 'EOF'
lines = open('include/linux/susfs.h').readlines()
new_code = '/* try_umount */\n'
new_code += '#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT\n'
new_code += 'void susfs_add_try_umount(void __user **user_info);\n'
new_code += 'void susfs_try_umount(uid_t uid);\n'
new_code += '#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT\n'
lines.insert(174, new_code)
open('include/linux/susfs.h', 'w').writelines(lines)
print("Done!")
EOF

python3 << 'EOF'
lines = open('include/linux/susfs.h').readlines()
new_code = '/* try_umount */\n'
new_code += '#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT\n'
new_code += 'struct st_susfs_try_umount {\n'
new_code += '\tchar                                    target_pathname[SUSFS_MAX_LEN_PATHNAME];\n'
new_code += '\tint                                     mnt_mode;\n'
new_code += '\tint                                     err;\n'
new_code += '};\n'
new_code += '\n'
new_code += 'struct st_susfs_try_umount_list {\n'
new_code += '\tstruct list_head                        list;\n'
new_code += '\tstruct st_susfs_try_umount              info;\n'
new_code += '};\n'
new_code += '#endif\n'
lines.insert(78, new_code)
open('include/linux/susfs.h', 'w').writelines(lines)
print("Done!")
EOF

python3 << 'EOF'
lines = open('fs/susfs.c').readlines()
new_code = '#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT\n'
new_code += '\tinfo->err = copy_config_to_buf("CONFIG_KSU_SUSFS_TRY_UMOUNT\\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);\n'
new_code += '\tif (info->err) goto out_copy_to_user;\n'
new_code += '\tbuf_ptr = info->enabled_features + copied_size;\n'
new_code += '#endif\n'
lines.insert(784, new_code)
open('fs/susfs.c', 'w').writelines(lines)
print("Done!")
EOF

python3 << 'EOF'
lines = open('fs/susfs.c').readlines()
new_code  = '/* try_umount */\n'
new_code += '#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT\n'
new_code += 'static DEFINE_SPINLOCK(susfs_spin_lock_try_umount);\n'
new_code += 'extern void try_umount(const char *mnt, int flags);\n'
new_code += 'static LIST_HEAD(LH_TRY_UMOUNT_PATH);\n'
new_code += 'void susfs_add_try_umount(void __user **user_info) {\n'
new_code += '\tstruct st_susfs_try_umount info = {0};\n'
new_code += '\tstruct st_susfs_try_umount_list *new_list = NULL;\n'
new_code += '\n'
new_code += '\tif (copy_from_user(&info, (struct st_susfs_try_umount __user*)*user_info, sizeof(info))) {\n'
new_code += '\t\tinfo.err = -EFAULT;\n'
new_code += '\t\tgoto out_copy_to_user;\n'
new_code += '\t}\n'
new_code += '\n'
new_code += '\tif (info.mnt_mode == TRY_UMOUNT_DEFAULT) {\n'
new_code += '\t\tinfo.mnt_mode = 0;\n'
new_code += '\t} else if (info.mnt_mode == TRY_UMOUNT_DETACH) {\n'
new_code += '\t\tinfo.mnt_mode = MNT_DETACH;\n'
new_code += '\t} else {\n'
new_code += '\t\tSUSFS_LOGE("Unsupported mnt_mode: %d\\n", info.mnt_mode);\n'
new_code += '\t\tinfo.err = -EINVAL;\n'
new_code += '\t\tgoto out_copy_to_user;\n'
new_code += '\t}\n'
new_code += '\n'
new_code += '\tnew_list = kmalloc(sizeof(struct st_susfs_try_umount_list), GFP_KERNEL);\n'
new_code += '\tif (!new_list) {\n'
new_code += '\t\tinfo.err = -ENOMEM;\n'
new_code += '\t\tgoto out_copy_to_user;\n'
new_code += '\t}\n'
new_code += '\n'
new_code += '\tmemcpy(&new_list->info, &info, sizeof(info));\n'
new_code += '\n'
new_code += '\tINIT_LIST_HEAD(&new_list->list);\n'
new_code += '\tspin_lock(&susfs_spin_lock_try_umount);\n'
new_code += '\tlist_add_tail(&new_list->list, &LH_TRY_UMOUNT_PATH);\n'
new_code += '\tspin_unlock(&susfs_spin_lock_try_umount);\n'
new_code += '\tSUSFS_LOGI("target_pathname: \'%s\', umount options: %d, is successfully added to LH_TRY_UMOUNT_PATH\\n", new_list->info.target_pathname, new_list->info.mnt_mode);\n'
new_code += '\tinfo.err = 0;\n'
new_code += 'out_copy_to_user:\n'
new_code += '\tif (copy_to_user(&((struct st_susfs_try_umount __user*)*user_info)->err, &info.err, sizeof(info.err))) {\n'
new_code += '\t\tinfo.err = -EFAULT;\n'
new_code += '\t}\n'
new_code += '\tSUSFS_LOGI("CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\\n", info.err);\n'
new_code += '}\n'
new_code += '\n'
new_code += 'void susfs_try_umount(uid_t uid) {\n'
new_code += '\tstruct st_susfs_try_umount_list *cursor = NULL;\n'
new_code += '\n'
new_code += '\t// We should umount in reversed order\n'
new_code += '\tlist_for_each_entry_reverse(cursor, &LH_TRY_UMOUNT_PATH, list) {\n'
new_code += '\t\tSUSFS_LOGI("umounting \'%s\' for uid: %u\\n", cursor->info.target_pathname, uid);\n'
new_code += '\t\ttry_umount(cursor->info.target_pathname, cursor->info.mnt_mode);\n'
new_code += '\t}\n'
new_code += '}\n'
new_code += '#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT\n'
lines.insert(449, new_code)
open('fs/susfs.c', 'w').writelines(lines)
print("Done!")
EOF

# Moving new files
rm -rf drivers/kernelsu/setuid_hook.c
rm -rf fs/readdir.c
rm -rf fs/notify/fdinfo.c
rm -rf drivers/kernelsu/supercalls.c

mv setuid_hook.c drivers/kernelsu/
mv readdir.c fs/
mv fdinfo.c fs/notify/
mv supercalls.c drivers/kernelsu