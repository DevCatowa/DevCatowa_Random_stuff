#!/usr/bin/env python3
"""
patch_multi_manager.py
Ports Multi Manager Support from ReSukiSU into a KernelSU kernel/ directory.

Usage:
    python3 patch_multi_manager.py <path-to-KernelSU/kernel>
"""

import os
import sys

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  [OK] {os.path.basename(path)}")

def patch(content, old, new, label):
    if old not in content:
        print(f"  [FAIL] anchor not found: {label}")
        sys.exit(1)
    return content.replace(old, new, 1)

# ---------------------------------------------------------------------------
# new file contents
# ---------------------------------------------------------------------------

DYNAMIC_MANAGER_H = r"""#ifndef __KSU_H_DYNAMIC_MANAGER
#define __KSU_H_DYNAMIC_MANAGER

#include <linux/types.h>
#include "ksu.h"
#include "supercalls.h"
#include "manager_sign.h"

#define DYNAMIC_MANAGER_SIGNATURE_INDEX_MAGIC 255

struct dynamic_manager_config {
    unsigned size;
    char hash[65];
    int is_set;
};

// Dynamic sign operations
void ksu_dynamic_manager_init(void);
void ksu_dynamic_manager_exit(void);
int ksu_handle_dynamic_manager(struct ksu_dynamic_manager_cmd *cmd);
bool ksu_is_dynamic_manager_enabled(void);
apk_sign_key_t ksu_get_dynamic_manager_sign(void);

#endif
"""

DYNAMIC_MANAGER_C = r"""#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "throne_tracker.h"
#include "dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "ksu.h"

static struct dynamic_manager_config dynamic_manager = {
    .size  = 0x300,
    .hash  = "0000000000000000000000000000000000000000000000000000000000000000",
    .is_set = 0
};

bool ksu_is_dynamic_manager_enabled(void)
{
    return dynamic_manager.is_set;
}

apk_sign_key_t ksu_get_dynamic_manager_sign(void)
{
    apk_sign_key_t sign_key = {
        .size   = dynamic_manager.size,
        .sha256 = dynamic_manager.hash
    };
    return sign_key;
}

int ksu_handle_dynamic_manager(struct ksu_dynamic_manager_cmd *cmd)
{
    int ret = 0;
    int i;

    if (!cmd)
        return -EINVAL;

    switch (cmd->operation) {
    case DYNAMIC_MANAGER_OP_SET:
        if (cmd->size < 0x100 || cmd->size > 0x1000) {
            pr_err("dynamic_manager: invalid size: 0x%x\n", cmd->size);
            return -EINVAL;
        }
        for (i = 0; i < 64; i++) {
            char c = cmd->hash[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                pr_err("dynamic_manager: invalid hash char at %d: %c\n", i, c);
                return -EINVAL;
            }
        }
        if (dynamic_manager.is_set)
            ksu_unregister_manager_by_signature_index(
                DYNAMIC_MANAGER_SIGNATURE_INDEX_MAGIC);

        dynamic_manager.size = cmd->size;
        memcpy(dynamic_manager.hash, cmd->hash, 64);
        dynamic_manager.hash[64] = '\0';
        dynamic_manager.is_set = 1;

        track_throne(false, true);
        pr_info("dynamic manager updated: size=0x%x, hash=%.16s...\n",
                cmd->size, cmd->hash);
        break;

    case DYNAMIC_MANAGER_OP_GET:
        if (dynamic_manager.is_set) {
            cmd->size = dynamic_manager.size;
            memcpy(cmd->hash, dynamic_manager.hash, 64);
        } else {
            ret = -ENODATA;
        }
        break;

    case DYNAMIC_MANAGER_OP_WIPE:
        dynamic_manager.is_set = 0;
        ksu_unregister_manager_by_signature_index(
            DYNAMIC_MANAGER_SIGNATURE_INDEX_MAGIC);
        pr_info("dynamic manager wiped\n");
        break;

    default:
        pr_err("dynamic_manager: invalid operation: %d\n", cmd->operation);
        return -EINVAL;
    }

    return ret;
}

void ksu_dynamic_manager_init(void) {}
void ksu_dynamic_manager_exit(void) {}
"""

MANAGER_H = r"""#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>
#include "allowlist.h"

#define PER_USER_RANGE 100000
#define KSU_INVALID_APPID -1

extern u16 ksu_last_manager_appid;

static inline void ksu_mark_manager(u32 uid)
{
    ksu_last_manager_appid = uid % PER_USER_RANGE;
}

extern bool is_manager(void);
bool ksu_is_manager_appid(u16 appid);
extern bool ksu_is_manager_uid(u32 uid);
extern void ksu_register_manager(u32 uid, u8 signature_index);
extern void ksu_unregister_manager(u32 uid);
extern void ksu_unregister_manager_by_signature_index(u8 signature_index);
extern int ksu_get_manager_signature_index_by_appid(u16 appid);
extern bool ksu_has_manager(void);

int ksu_observer_init(void);
void ksu_observer_exit(void);

#endif
"""

MANAGER_C = r"""#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include "supercalls.h"
#include "manager.h"
#include "ksu.h"

u16 ksu_last_manager_appid = KSU_INVALID_APPID;

struct ksu_manager_node {
    u8 signature_index;
    u16 appid;
    struct list_head list;
    struct rcu_head rcu;
};

static LIST_HEAD(ksu_manager_appid_list);
static DEFINE_SPINLOCK(ksu_manager_list_write_lock);

bool ksu_is_manager_appid(u16 appid)
{
    bool found = false;
    struct ksu_manager_node *pos;

    rcu_read_lock();
    list_for_each_entry_rcu(pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

bool ksu_is_manager_uid(u32 uid)
{
    return ksu_is_manager_appid(uid % PER_USER_RANGE);
}

bool is_manager(void)
{
    return ksu_is_manager_uid(current_uid().val);
}

void ksu_register_manager(u32 uid, u8 signature_index)
{
    struct ksu_manager_node *node;
    u16 appid = uid % PER_USER_RANGE;

    if (ksu_is_manager_uid(uid))
        return;

    node = kzalloc(sizeof(*node), GFP_ATOMIC);
    if (unlikely(!node))
        return;

    node->appid = appid;
    node->signature_index = signature_index;

    spin_lock(&ksu_manager_list_write_lock);
    if (ksu_is_manager_uid(uid)) {
        spin_unlock(&ksu_manager_list_write_lock);
        kfree(node);
        return;
    }
    list_add_tail_rcu(&node->list, &ksu_manager_appid_list);
    spin_unlock(&ksu_manager_list_write_lock);

    if (ksu_last_manager_appid == KSU_INVALID_APPID)
        ksu_last_manager_appid = appid;
}

void ksu_unregister_manager(u32 uid)
{
    struct ksu_manager_node *pos, *tmp;
    u16 appid = uid % PER_USER_RANGE;
    bool mark_another = (ksu_last_manager_appid == appid);

    if (!ksu_is_manager_uid(uid))
        return;

    spin_lock(&ksu_manager_list_write_lock);
    list_for_each_entry_safe(pos, tmp, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            list_del_rcu(&pos->list);
            spin_unlock(&ksu_manager_list_write_lock);
            kfree_rcu(pos, rcu);
            if (mark_another)
                ksu_last_manager_appid = KSU_INVALID_APPID;
            return;
        }
    }
    spin_unlock(&ksu_manager_list_write_lock);
}

void ksu_unregister_manager_by_signature_index(u8 signature_index)
{
    struct ksu_manager_node *pos, *tmp;
    u16 last_alive = KSU_INVALID_APPID;
    bool mark_another = false;

    spin_lock(&ksu_manager_list_write_lock);
    list_for_each_entry_safe(pos, tmp, &ksu_manager_appid_list, list) {
        if (pos->signature_index == signature_index) {
            if (pos->appid == ksu_last_manager_appid)
                mark_another = true;
            list_del_rcu(&pos->list);
            spin_unlock(&ksu_manager_list_write_lock);
            kfree_rcu(pos, rcu);
            if (mark_another)
                ksu_last_manager_appid = last_alive;
            return;
        }
        last_alive = pos->appid;
    }
    spin_unlock(&ksu_manager_list_write_lock);
}

bool ksu_has_manager(void)
{
    bool empty;
    rcu_read_lock();
    empty = list_empty(&ksu_manager_appid_list);
    rcu_read_unlock();
    return !empty;
}

int ksu_handle_get_managers_cmd(struct ksu_get_managers_cmd __user *arg,
                                struct ksu_get_managers_cmd *cmd)
{
    struct ksu_manager_node *pos;
    int count = 0;
    u16 max_allowed = cmd->count;

    rcu_read_lock();
    list_for_each_entry_rcu(pos, &ksu_manager_appid_list, list) {
        if (count < max_allowed) {
            struct ksu_manager_entry entry = {
                .uid = pos->appid,
                .signature_index = pos->signature_index
            };
            void __user *dest =
                (void __user *)((char *)arg +
                    sizeof(struct ksu_get_managers_cmd) +
                    (count * sizeof(struct ksu_manager_entry)));
            if (copy_to_user(dest, &entry, sizeof(entry))) {
                rcu_read_unlock();
                return -EFAULT;
            }
        }
        count++;
    }
    rcu_read_unlock();

    cmd->total_count = count;
    return 0;
}

int ksu_get_manager_signature_index_by_appid(u16 appid)
{
    struct ksu_manager_node *pos;

    rcu_read_lock();
    list_for_each_entry_rcu(pos, &ksu_manager_appid_list, list) {
        if (pos->appid == appid) {
            rcu_read_unlock();
            return pos->signature_index;
        }
    }
    rcu_read_unlock();
    return -ENODATA;
}
"""

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-KernelSU/kernel>")
        sys.exit(1)

    kdir = sys.argv[1].rstrip("/")
    if not os.path.isdir(kdir):
        print(f"ERROR: directory not found: {kdir}")
        sys.exit(1)

    print(f"\n[*] Target: {kdir}\n")

    # ------------------------------------------------------------------
    # 1-3: Write new files
    # ------------------------------------------------------------------
    print("[1/13] Writing dynamic_manager.h")
    write(os.path.join(kdir, "dynamic_manager.h"), DYNAMIC_MANAGER_H)

    print("[2/13] Writing dynamic_manager.c")
    write(os.path.join(kdir, "dynamic_manager.c"), DYNAMIC_MANAGER_C)

    print("[3/13] Writing manager.c")
    write(os.path.join(kdir, "manager.c"), MANAGER_C)

    # ------------------------------------------------------------------
    # 4: Replace manager.h
    # ------------------------------------------------------------------
    print("[4/13] Replacing manager.h")
    write(os.path.join(kdir, "manager.h"), MANAGER_H)

    # ------------------------------------------------------------------
    # 5: manager_sign.h
    # ------------------------------------------------------------------
    print("[5/13] Patching manager_sign.h")
    p = os.path.join(kdir, "manager_sign.h")
    c = read(p)

    c = patch(c,
        '// KOWX712/KernelSU\n',
        ('// SukiSU-Ultra/SukiSU-Ultra\n'
         '#define EXPECTED_SIZE_SUKISU 0x35c\n'
         '#define EXPECTED_HASH_SUKISU \\\n'
         '\t"947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"\n\n'
         '// ReSukiSU/ReSukiSU\n'
         '#define EXPECTED_SIZE_RESUKISU 0x377\n'
         '#define EXPECTED_HASH_RESUKISU \\\n'
         '\t"d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64"\n\n'
         '// KOWX712/KernelSU\n'),
        "manager_sign.h hashes")

    c = c.replace('\tu32 size;\n', '\tunsigned size;\n', 1)
    write(p, c)

    # ------------------------------------------------------------------
    # 6: apk_sign.h
    # ------------------------------------------------------------------
    print("[6/13] Patching apk_sign.h")
    p = os.path.join(kdir, "apk_sign.h")
    c = read(p)
    c = patch(c,
        'bool is_manager_apk(char *path);',
        ('bool is_manager_apk(char *path, u8 *signature_index);\n'
         'int get_pkg_from_apk_path(char *pkg, const char *path);'),
        "apk_sign.h")
    if '#include "ksu.h"' not in c:
        c = patch(c, '#include <linux/types.h>\n',
                  '#include <linux/types.h>\n#include "ksu.h"\n',
                  "apk_sign.h ksu include")
    write(p, c)

    # ------------------------------------------------------------------
    # 7: apk_sign.c
    # ------------------------------------------------------------------
    print("[7/13] Patching apk_sign.c")
    p = os.path.join(kdir, "apk_sign.c")
    c = read(p)

    # 7a. dynamic_manager include
    c = patch(c,
        '#include "manager_sign.h"\n',
        '#include "manager_sign.h"\n#include "dynamic_manager.h"\n',
        "apk_sign.c include")

    # 7b. apk_sign_keys[] array
    c = patch(c,
        ('static apk_sign_key_t apk_sign_keys[] = {\n'
         '\t{ EXPECTED_SIZE_OFFICIAL, EXPECTED_HASH_OFFICIAL }, // Official\n'
         '\t{ EXPECTED_SIZE_RSUNTK, EXPECTED_HASH_RSUNTK }, // RKSU\n'
         '\t{ EXPECTED_SIZE_5EC1CFF, EXPECTED_HASH_5EC1CFF }, // MKSU\n'
         '\t{ EXPECTED_SIZE_KOWX712, EXPECTED_HASH_KOWX712 }, // KowSU\n'
         '#ifdef EXPECTED_SIZE\n'
         '\t{ EXPECTED_SIZE, EXPECTED_HASH }, // Custom\n'
         '#endif\n'
         '};'),
        ('static apk_sign_key_t apk_sign_keys[] = {\n'
         '\t{ EXPECTED_SIZE_RESUKISU, EXPECTED_HASH_RESUKISU }, /* ReSukiSU */\n'
         '#ifdef CONFIG_KSU_MULTI_MANAGER_SUPPORT\n'
         '\t{ EXPECTED_SIZE_OFFICIAL, EXPECTED_HASH_OFFICIAL }, // tiann/KernelSU\n'
         '\t{ EXPECTED_SIZE_5EC1CFF, EXPECTED_HASH_5EC1CFF }, // 5ec1cff/KernelSU\n'
         '\t{ EXPECTED_SIZE_RSUNTK, EXPECTED_HASH_RSUNTK }, // rsuntk/KernelSU\n'
         '\t{ EXPECTED_SIZE_SUKISU, EXPECTED_HASH_SUKISU }, // SukiSU-Ultra\n'
         '\t{ EXPECTED_SIZE_KOWX712, EXPECTED_HASH_KOWX712 }, // KOWX712\n'
         '#endif\n'
         '#ifdef EXPECTED_SIZE\n'
         '\t{ EXPECTED_SIZE, EXPECTED_HASH }, // Custom\n'
         '#endif\n'
         '};'),
        "apk_sign.c keys")

    # 7c. check_block: add matched_index param + rewrite internals
    c = patch(c,
        ('static bool check_block(struct file *fp, u32 *size4, loff_t *pos, u32 *offset)\n'
         '{\n'
         '\tint i;\n'
         '\tapk_sign_key_t sign_key;\n'
         '\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // signer-sequence length\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // signer length\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // signed data length\n'
         '\n'
         '\t*offset += 0x4 * 3;\n'
         '\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // digests-sequence length\n'
         '\n'
         '\t*pos += *size4;\n'
         '\t*offset += 0x4 + *size4;\n'
         '\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // certificates length\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // certificate length\n'
         '\t*offset += 0x4 * 2;\n'
         '\n'
         '\tfor (i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {\n'
         '\t\tsign_key = apk_sign_keys[i];\n'
         '\n'
         '\t\tif (*size4 != sign_key.size)\n'
         '\t\t\tcontinue;\n'
         '\t\t*offset += *size4;\n'
         '\n'
         '#define CERT_MAX_LENGTH 1024\n'
         '\t\tchar cert[CERT_MAX_LENGTH];\n'
         '\t\tif (*size4 > CERT_MAX_LENGTH) {\n'
         '\t\t\tpr_info("cert length overlimit\\n");\n'
         '\t\t\treturn false;\n'
         '\t\t}\n'
         '\t\tksu_kernel_read_compat(fp, cert, *size4, pos);\n'
         '\t\tunsigned char digest[SHA256_DIGEST_SIZE];\n'
         '\t\tif (ksu_sha256(cert, *size4, digest) < 0) {\n'
         '\t\t\tpr_info("sha256 error\\n");\n'
         '\t\t\treturn false;\n'
         '\t\t}\n'
         '\n'
         '\t\tchar hash_str[SHA256_DIGEST_SIZE * 2 + 1];\n'
         '\t\thash_str[SHA256_DIGEST_SIZE * 2] = \'\\0\';\n'
         '\n'
         '\t\tbin2hex(hash_str, digest, SHA256_DIGEST_SIZE);\n'
         '\t\tpr_info("sha256: %s, expected: %s\\n", hash_str,\n'
         '\t\t\tsign_key.sha256);\n'
         '\t\tif (strcmp(sign_key.sha256, hash_str) == 0) {\n'
         '\t\t\treturn true;\n'
         '\t\t}\n'
         '\t}\n'
         '\treturn false;\n'
         '}\n'),
        ('static bool check_block(struct file *fp, u32 *size4, loff_t *pos,\n'
         '                        u32 *offset, u8 *matched_index)\n'
         '{\n'
         '\tu8 i;\n'
         '\tapk_sign_key_t sign_key;\n'
         '\tbool signature_valid = false;\n'
         '\tunsigned char digest[SHA256_DIGEST_SIZE];\n'
         '\tchar hash_str[SHA256_DIGEST_SIZE * 2 + 1];\n'
         '#define CERT_MAX_LENGTH 1024\n'
         '\tchar cert[CERT_MAX_LENGTH];\n'
         '\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // signer-sequence length\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // signer length\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // signed data length\n'
         '\n'
         '\t*offset += 0x4 * 3;\n'
         '\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // digests-sequence length\n'
         '\n'
         '\t*pos += *size4;\n'
         '\t*offset += 0x4 + *size4;\n'
         '\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // certificates length\n'
         '\tksu_kernel_read_compat(fp, size4, 0x4, pos); // certificate length\n'
         '\t*offset += 0x4 * 2;\n'
         '\n'
         '\tif (*size4 > CERT_MAX_LENGTH) {\n'
         '\t\tpr_info("cert length overlimit: %u\\n", *size4);\n'
         '\t\treturn false;\n'
         '\t}\n'
         '\tif (ksu_kernel_read_compat(fp, cert, *size4, pos) != *size4)\n'
         '\t\treturn false;\n'
         '\tif (ksu_sha256(cert, *size4, digest) < 0) {\n'
         '\t\tpr_err("sha256 error\\n");\n'
         '\t\treturn false;\n'
         '\t}\n'
         '\tbin2hex(hash_str, digest, SHA256_DIGEST_SIZE);\n'
         '\thash_str[SHA256_DIGEST_SIZE * 2] = \'\\0\';\n'
         '\n'
         '\tBUILD_BUG_ON(ARRAY_SIZE(apk_sign_keys) >= 255);\n'
         '\tfor (i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {\n'
         '\t\tsign_key = apk_sign_keys[i];\n'
         '\t\tif (*size4 == sign_key.size &&\n'
         '\t\t    strcmp(sign_key.sha256, hash_str) == 0) {\n'
         '\t\t\tif (matched_index)\n'
         '\t\t\t\t*matched_index = i;\n'
         '\t\t\tsignature_valid = true;\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t}\n'
         '\n'
         '\tif (!signature_valid && ksu_is_dynamic_manager_enabled()) {\n'
         '\t\tsign_key = ksu_get_dynamic_manager_sign();\n'
         '\t\tif (*size4 == sign_key.size &&\n'
         '\t\t    strcmp(sign_key.sha256, hash_str) == 0) {\n'
         '\t\t\tif (matched_index)\n'
         '\t\t\t\t*matched_index =\n'
         '\t\t\t\t\tDYNAMIC_MANAGER_SIGNATURE_INDEX_MAGIC;\n'
         '\t\t\tsignature_valid = true;\n'
         '\t\t}\n'
         '\t}\n'
         '\n'
         '\t*offset += *size4;\n'
         '\treturn signature_valid;\n'
         '}'),
        "apk_sign.c check_block")

    # 7d. check_v2_signature: add signature_index param + matched_index local
    c = patch(c,
        'static __always_inline bool check_v2_signature(char *path)\n{',
        ('static __always_inline bool check_v2_signature(char *path,\n'
         '\t\t\t\t\t\t    u8 *signature_index)\n'
         '{\n'
         '\tu8 matched_index = (u8)-1;'),
        "apk_sign.c check_v2_signature sig")

    # 7e. update check_block call inside check_v2_signature
    c = patch(c,
        ('\t\t\tv2_signing_valid =\n'
         '\t\t\t\tcheck_block(fp, &size4, &pos, &offset);'),
        ('\t\t\tv2_signing_valid =\n'
         '\t\t\t\tcheck_block(fp, &size4, &pos, &offset,\n'
         '\t\t\t\t\t    &matched_index);'),
        "apk_sign.c check_block call")

    # 7f. update return — propagate matched_index
    c = patch(c,
        ('\tif (v3_signing_exist || v3_1_signing_exist) {\n'
         '#ifdef CONFIG_KSU_DEBUG\n'
         '\t\tpr_err("Unexpected v3 signature scheme found!\\n");\n'
         '#endif\n'
         '\t\treturn false;\n'
         '\t}\n'
         '\n'
         '\treturn v2_signing_valid;\n'
         '}'),
        ('\tif (v3_signing_exist || v3_1_signing_exist) {\n'
         '#ifdef CONFIG_KSU_DEBUG\n'
         '\t\tpr_err("Unexpected v3 signature scheme found!\\n");\n'
         '#endif\n'
         '\t\treturn false;\n'
         '\t}\n'
         '\n'
         '\tif (v2_signing_valid && signature_index)\n'
         '\t\t*signature_index = matched_index;\n'
         '\n'
         '\treturn v2_signing_valid;\n'
         '}'),
        "apk_sign.c return")

    # 7g. replace is_manager_apk + add get_pkg_from_apk_path before it
    c = patch(c,
        ('bool is_manager_apk(char *path)\n'
         '{\n'
         '\treturn check_v2_signature(path);\n'
         '}'),
        ('int get_pkg_from_apk_path(char *pkg, const char *path)\n'
         '{\n'
         '\tint len = strlen(path);\n'
         '\tif (len >= KSU_MAX_PACKAGE_NAME || len < 1)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tconst char *last_slash = NULL;\n'
         '\tconst char *second_last_slash = NULL;\n'
         '\tint i;\n'
         '\tfor (i = len - 1; i >= 0; i--) {\n'
         '\t\tif (path[i] == \'/\') {\n'
         '\t\t\tif (!last_slash)\n'
         '\t\t\t\tlast_slash = &path[i];\n'
         '\t\t\telse {\n'
         '\t\t\t\tsecond_last_slash = &path[i];\n'
         '\t\t\t\tbreak;\n'
         '\t\t\t}\n'
         '\t\t}\n'
         '\t}\n'
         '\tif (!last_slash || !second_last_slash)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tconst char *last_hyphen = strchr(second_last_slash, \'-\');\n'
         '\tif (!last_hyphen || last_hyphen > last_slash)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tint pkg_len = last_hyphen - second_last_slash - 1;\n'
         '\tif (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tstrncpy(pkg, second_last_slash + 1, pkg_len);\n'
         '\tpkg[pkg_len] = \'\\0\';\n'
         '\treturn 0;\n'
         '}\n'
         '\n'
         'bool is_manager_apk(char *path, u8 *signature_index)\n'
         '{\n'
         '#ifdef KSU_MANAGER_PACKAGE\n'
         '\tchar pkg[KSU_MAX_PACKAGE_NAME];\n'
         '\tif (get_pkg_from_apk_path(pkg, path) < 0)\n'
         '\t\treturn false;\n'
         '\tif (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE)))\n'
         '\t\treturn false;\n'
         '#endif\n'
         '\treturn check_v2_signature(path, signature_index);\n'
         '}'),
        "apk_sign.c is_manager_apk")

    write(p, c)

    # ------------------------------------------------------------------
    # 8: supercalls.h
    # ------------------------------------------------------------------
    print("[8/13] Patching supercalls.h")
    p = os.path.join(kdir, "supercalls.h")
    c = read(p)

    c = patch(c,
        '// IOCTL command definitions\n',
        ('// Dynamic Manager\n'
         '#define DYNAMIC_MANAGER_OP_SET  0\n'
         '#define DYNAMIC_MANAGER_OP_GET  1\n'
         '#define DYNAMIC_MANAGER_OP_WIPE 2\n'
         '\n'
         'struct ksu_dynamic_manager_cmd {\n'
         '\tunsigned int operation;\n'
         '\tunsigned int size;\n'
         '\tchar hash[64];\n'
         '};\n'
         '\n'
         'struct ksu_manager_entry {\n'
         '\t__u32 uid;\n'
         '\t__u8  signature_index;\n'
         '} __attribute__((packed));\n'
         '\n'
         'struct ksu_get_managers_cmd {\n'
         '\t__u16 count;       // Input/Output: slots/managers returned\n'
         '\t__u16 total_count; // Output: total registered managers\n'
         '\tstruct ksu_manager_entry managers[];\n'
         '} __attribute__((packed));\n'
         '\n'
         '// IOCTL command definitions\n'),
        "supercalls.h structs")

    c = patch(c,
        '// IOCTL handler types\n',
        ('#define KSU_IOCTL_DYNAMIC_MANAGER \\\n'
         '\t_IOC(_IOC_READ | _IOC_WRITE, \'K\', 103, 0)\n'
         '// 104 = old get_managers, deprecated\n'
         '#define KSU_IOCTL_GET_MANAGERS \\\n'
         '\t_IOC(_IOC_READ | _IOC_WRITE, \'K\', 105, 0)\n'
         '\n'
         '// IOCTL handler types\n'),
        "supercalls.h new ioctls")

    write(p, c)

    # ------------------------------------------------------------------
    # 9: supercalls.c
    # ------------------------------------------------------------------
    print("[9/13] Patching supercalls.c")
    p = os.path.join(kdir, "supercalls.c")
    c = read(p)

    if '#include "dynamic_manager.h"' not in c:
        c = patch(c,
            '#include "kernel_umount.h"\n',
            '#include "kernel_umount.h"\n#include "dynamic_manager.h"\n',
            "supercalls.c include")

    c = patch(c,
        'static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {',
        ('static int do_dynamic_manager(void __user *arg)\n'
         '{\n'
         '\tstruct ksu_dynamic_manager_cmd cmd;\n'
         '\tif (copy_from_user(&cmd, arg, sizeof(cmd)))\n'
         '\t\treturn -EFAULT;\n'
         '\n'
         '\tint ret = ksu_handle_dynamic_manager(&cmd);\n'
         '\tif (ret)\n'
         '\t\treturn ret;\n'
         '\n'
         '\tif (cmd.operation == DYNAMIC_MANAGER_OP_GET &&\n'
         '\t    copy_to_user(arg, &cmd, sizeof(cmd)))\n'
         '\t\treturn -EFAULT;\n'
         '\n'
         '\treturn 0;\n'
         '}\n'
         '\n'
         'extern int ksu_handle_get_managers_cmd(\n'
         '\tstruct ksu_get_managers_cmd __user *arg,\n'
         '\tstruct ksu_get_managers_cmd *cmd);\n'
         '\n'
         'static int do_get_managers(void __user *arg)\n'
         '{\n'
         '\tstruct ksu_get_managers_cmd cmd;\n'
         '\tif (copy_from_user(&cmd, arg, sizeof(cmd)))\n'
         '\t\treturn -EFAULT;\n'
         '\n'
         '\tint ret = ksu_handle_get_managers_cmd(arg, &cmd);\n'
         '\tif (ret)\n'
         '\t\treturn ret;\n'
         '\n'
         '\tif (copy_to_user(arg, &cmd, sizeof(cmd)))\n'
         '\t\treturn -EFAULT;\n'
         '\n'
         '\treturn 0;\n'
         '}\n'
         '\n'
         'static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {'),
        "supercalls.c handlers")

    c = patch(c,
        ('\t// Sentinel\n'
         '\t{ .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL }\n'
         '};'),
        ('\tKSU_IOCTL(DYNAMIC_MANAGER, "SET_DYNAMIC_MANAGER",\n'
         '\t\t  do_dynamic_manager, only_root),\n'
         '\tKSU_IOCTL(GET_MANAGERS, "GET_MANAGERS",\n'
         '\t\t  do_get_managers, manager_or_root),\n'
         '\n'
         '\t// Sentinel\n'
         '\t{ .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL }\n'
         '};'),
        "supercalls.c ioctl table")

    write(p, c)

    # ------------------------------------------------------------------
    # 10: throne_tracker.h
    # ------------------------------------------------------------------
    print("[10/13] Patching throne_tracker.h")
    p = os.path.join(kdir, "throne_tracker.h")
    c = read(p)
    c = patch(c,
        'void track_throne(bool prune_only);',
        'void track_throne(bool prune_only, bool force_search_manager);',
        "throne_tracker.h")
    write(p, c)

    # ------------------------------------------------------------------
    # 11: throne_tracker.c
    # ------------------------------------------------------------------
    print("[11/13] Patching throne_tracker.c")
    p = os.path.join(kdir, "throne_tracker.c")
    c = read(p)

    # 11a. replace top block (includes + globals + uid_data struct)
    c = patch(c,
        ('#include <linux/err.h>\n'
         '#include <linux/fs.h>\n'
         '#include <linux/list.h>\n'
         '#include <linux/slab.h>\n'
         '#include <linux/string.h>\n'
         '#include <linux/types.h>\n'
         '#include <linux/version.h>\n'
         '\n'
         '#include "allowlist.h"\n'
         '#include "klog.h" // IWYU pragma: keep\n'
         '#include "manager.h"\n'
         '#include "kernel_compat.h"\n'
         '#include "throne_tracker.h"\n'
         '\n'
         'uid_t ksu_manager_appid = KSU_INVALID_APPID;\n'
         '\n'
         '#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list.tmp"\n'
         '\n'
         'struct uid_data {\n'
         '\tstruct list_head list;\n'
         '\tu32 uid;\n'
         '\tchar package[KSU_MAX_PACKAGE_NAME];\n'
         '};'),
        ('#include <linux/err.h>\n'
         '#include <linux/fs.h>\n'
         '#include <linux/list.h>\n'
         '#include <linux/slab.h>\n'
         '#include <linux/bitmap.h>\n'
         '#include <linux/string.h>\n'
         '#include <linux/types.h>\n'
         '#include <linux/version.h>\n'
         '#include <linux/stat.h>\n'
         '#include <linux/namei.h>\n'
         '\n'
         '#include "allowlist.h"\n'
         '#include "apk_sign.h"\n'
         '#include "klog.h" // IWYU pragma: keep\n'
         '#include "manager.h"\n'
         '#include "kernel_compat.h"\n'
         '#include "throne_tracker.h"\n'
         '#include "dynamic_manager.h"\n'
         '\n'
         '#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"\n'
         '#define MAX_APP_ID 10000\n'
         '\n'
         'struct uid_data {\n'
         '\tstruct list_head list;\n'
         '\tu32 uid;\n'
         '\tchar package[KSU_MAX_PACKAGE_NAME];\n'
         '};\n'
         '\n'
         'static unsigned long *last_app_id_map = NULL;\n'
         'static DEFINE_MUTEX(app_list_lock);'),
        "throne_tracker.c top block")

    # 11b. replace get_pkg_from_apk_path + old crown_manager
    c = patch(c,
        ('static int get_pkg_from_apk_path(char *pkg, const char *path)\n'
         '{\n'
         '\tint len = strlen(path);\n'
         '\tif (len >= KSU_MAX_PACKAGE_NAME || len < 1)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tconst char *last_slash = NULL;\n'
         '\tconst char *second_last_slash = NULL;\n'
         '\n'
         '\tint i;\n'
         '\tfor (i = len - 1; i >= 0; i--) {\n'
         '\t\tif (path[i] == \'/\') {\n'
         '\t\t\tif (!last_slash) {\n'
         '\t\t\t\tlast_slash = &path[i];\n'
         '\t\t\t} else {\n'
         '\t\t\t\tsecond_last_slash = &path[i];\n'
         '\t\t\t\tbreak;\n'
         '\t\t\t}\n'
         '\t\t}\n'
         '\t}\n'
         '\n'
         '\tif (!last_slash || !second_last_slash)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tconst char *last_hyphen = strchr(second_last_slash, \'-\');\n'
         '\tif (!last_hyphen || last_hyphen > last_slash)\n'
         '\t\treturn -1;\n'
         '\n'
         '\tint pkg_len = last_hyphen - second_last_slash - 1;\n'
         '\tif (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)\n'
         '\t\treturn -1;\n'
         '\n'
         '\t// Copying the package name\n'
         '\tstrncpy(pkg, second_last_slash + 1, pkg_len);\n'
         '\tpkg[pkg_len] = \'\\0\';\n'
         '\n'
         '\treturn 0;\n'
         '}\n'
         '\n'
         'static void crown_manager(const char *apk, struct list_head *uid_data)\n'
         '{\n'
         '\tchar pkg[KSU_MAX_PACKAGE_NAME];\n'
         '\tif (get_pkg_from_apk_path(pkg, apk) < 0) {\n'
         '\t\tpr_err("Failed to get package name from apk path: %s\\n", apk);\n'
         '\t\treturn;\n'
         '\t}\n'
         '\n'
         '\tpr_info("manager pkg: %s\\n", pkg);\n'
         '\n'
         '#ifdef KSU_MANAGER_PACKAGE\n'
         '\t// pkg is `/<real package>`\n'
         '\tif (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {\n'
         '\t\tpr_info("manager package is inconsistent with kernel build: %s\\n",\n'
         '\t\t\tKSU_MANAGER_PACKAGE);\n'
         '\t\treturn;\n'
         '\t}\n'
         '#endif\n'
         '\tstruct list_head *list = (struct list_head *)uid_data;\n'
         '\tstruct uid_data *np;\n'
         '\n'
         '\tlist_for_each_entry (np, list, list) {\n'
         '\t\tif (strncmp(np->package, pkg, KSU_MAX_PACKAGE_NAME) == 0) {\n'
         '\t\t\tpr_info("Crowning manager: %s(uid=%d)\\n", pkg, np->uid);\n'
         '\t\t\tksu_set_manager_appid(np->uid);\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t}\n'
         '}'),
        ('static void crown_manager(const char *apk, struct list_head *uid_data,\n'
         '\t\t\t   u8 signature_index)\n'
         '{\n'
         '\tchar pkg[KSU_MAX_PACKAGE_NAME];\n'
         '\tstruct uid_data *np;\n'
         '\n'
         '\tif (get_pkg_from_apk_path(pkg, apk) < 0) {\n'
         '\t\tpr_err("Failed to get pkg from: %s\\n", apk);\n'
         '\t\treturn;\n'
         '\t}\n'
         '\tpr_info("manager pkg: %s\\n", pkg);\n'
         '\n'
         '\tlist_for_each_entry(np, uid_data, list) {\n'
         '\t\tif (strncmp(np->package, pkg, KSU_MAX_PACKAGE_NAME) == 0) {\n'
         '\t\t\tpr_info("Crowning: %s uid=%d sig=%d\\n",\n'
         '\t\t\t\tpkg, np->uid, signature_index);\n'
         '\t\t\tksu_register_manager(np->uid, signature_index);\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t}\n'
         '}'),
        "throne_tracker.c crown_manager")

    # 11c. update extern is_manager_apk declaration
    c = patch(c,
        'extern bool is_manager_apk(char *path);\n',
        'extern bool is_manager_apk(char *path, u8 *signature_index);\n',
        "throne_tracker.c extern decl")

    # 11d. remove stop field from my_dir_context
    c = patch(c,
        ('struct my_dir_context {\n'
         '\tstruct dir_context ctx;\n'
         '\tstruct list_head *data_path_list;\n'
         '\tchar *parent_dir;\n'
         '\tvoid *private_data;\n'
         '\tint depth;\n'
         '\tint *stop;\n'
         '};'),
        ('struct my_dir_context {\n'
         '\tstruct dir_context ctx;\n'
         '\tstruct list_head *data_path_list;\n'
         '\tchar *parent_dir;\n'
         '\tvoid *private_data;\n'
         '\tint depth;\n'
         '};'),
        "throne_tracker.c my_dir_context")

    # 11e. remove stop early-exit check from my_actor
    c = patch(c,
        ('\tif (my_ctx->stop && *my_ctx->stop) {\n'
         '\t\tpr_info("Stop searching\\n");\n'
         '\t\treturn FILLDIR_ACTOR_STOP;\n'
         '\t}\n'
         '\n'),
        '',
        "throne_tracker.c stop check")

    # 11f. fix DT_DIR condition
    c = patch(c,
        ('\tif (d_type == DT_DIR && my_ctx->depth > 0 &&\n'
         '\t    (my_ctx->stop && !*my_ctx->stop)) {'),
        '\tif (d_type == DT_DIR && my_ctx->depth > 0) {',
        "throne_tracker.c DT_DIR condition")

    # 11g. update is_manager_apk call + crown_manager call in my_actor
    c = patch(c,
        ('\t\t\tbool is_manager = is_manager_apk(dirpath);\n'
         '\t\t\tprint_iter(is_manager, dirpath);\n'
         '\t\t\tif (is_manager) {\n'
         '\t\t\t\tcrown_manager(dirpath, my_ctx->private_data);\n'
         '\t\t\t\t*my_ctx->stop = 1;\n'
         '\t\t\t}'),
        ('\t\t\tu8 sig_idx = 0;\n'
         '\t\t\tbool is_manager = is_manager_apk(dirpath, &sig_idx);\n'
         '\t\t\tprint_iter(is_manager, dirpath);\n'
         '\t\t\tif (is_manager)\n'
         '\t\t\t\tcrown_manager(dirpath,\n'
         '\t\t\t\t\t      my_ctx->private_data,\n'
         '\t\t\t\t\t      sig_idx);'),
        "throne_tracker.c actor is_manager_apk")

    # 11h. remove stop from ctx initializer in search_manager
    c = patch(c,
        ('\t\t\tstruct my_dir_context ctx = { .ctx.actor = my_actor,\n'
         '\t\t\t\t\t\t      .data_path_list =\n'
         '\t\t\t\t\t\t\t      &data_path_list,\n'
         '\t\t\t\t\t\t      .parent_dir =\n'
         '\t\t\t\t\t\t\t      pos->dirpath,\n'
         '\t\t\t\t\t\t      .private_data = uid_data,\n'
         '\t\t\t\t\t\t      .depth = pos->depth,\n'
         '\t\t\t\t\t\t      .stop = &stop };'),
        ('\t\t\tstruct my_dir_context ctx = { .ctx.actor = my_actor,\n'
         '\t\t\t\t\t\t      .data_path_list =\n'
         '\t\t\t\t\t\t\t      &data_path_list,\n'
         '\t\t\t\t\t\t      .parent_dir =\n'
         '\t\t\t\t\t\t\t      pos->dirpath,\n'
         '\t\t\t\t\t\t      .private_data = uid_data,\n'
         '\t\t\t\t\t\t      .depth = pos->depth,\n'
         '\t\t\t\t\t\t      };'),
        "throne_tracker.c ctx init")

    # 11i. remove stop local var + stop guard in search_manager
    c = c.replace('\tint i, stop = 0;\n', '\tint i;\n', 1)
    c = c.replace('\t\t\tif (!stop) {\n', '\t\t\t{\n', 1)

    # 11j. replace entire track_throne function
    c = patch(c,
        ('void track_throne(bool prune_only)\n'
         '{\n'
         '\tstruct file *fp =\n'
         '\t\tksu_filp_open_compat(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);\n'
         '\tif (IS_ERR(fp)) {\n'
         '\t\tpr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\\n",\n'
         '\t\t       __func__, PTR_ERR(fp));\n'
         '\t\treturn;\n'
         '\t}\n'
         '\n'
         '\tstruct list_head uid_list;\n'
         '\tINIT_LIST_HEAD(&uid_list);\n'
         '\n'
         '\tchar chr = 0;\n'
         '\tloff_t pos = 0;\n'
         '\tloff_t line_start = 0;\n'
         '\tchar buf[KSU_MAX_PACKAGE_NAME];\n'
         '\tfor (;;) {\n'
         '\t\tssize_t count =\n'
         '\t\t\tksu_kernel_read_compat(fp, &chr, sizeof(chr), &pos);\n'
         '\t\tif (count != sizeof(chr))\n'
         '\t\t\tbreak;\n'
         '\t\tif (chr != \'\\n\')\n'
         '\t\t\tcontinue;\n'
         '\n'
         '\t\tcount = ksu_kernel_read_compat(fp, buf, sizeof(buf),\n'
         '\t\t\t\t\t       &line_start);\n'
         '\n'
         '\t\tstruct uid_data *data =\n'
         '\t\t\tkzalloc(sizeof(struct uid_data), GFP_ATOMIC);\n'
         '\t\tif (!data) {\n'
         '\t\t\tfilp_close(fp, 0);\n'
         '\t\t\tgoto out;\n'
         '\t\t}\n'
         '\n'
         '\t\tchar *tmp = buf;\n'
         '\t\tconst char *delim = " ";\n'
         '\t\tchar *package = strsep(&tmp, delim);\n'
         '\t\tchar *uid = strsep(&tmp, delim);\n'
         '\t\tif (!uid || !package) {\n'
         '\t\t\tpr_err("update_uid: package or uid is NULL!\\n");\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\n'
         '\t\tu32 res;\n'
         '\t\tif (kstrtou32(uid, 10, &res)) {\n'
         '\t\t\tpr_err("update_uid: uid parse err\\n");\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t\tdata->uid = res;\n'
         '\t\tstrncpy(data->package, package, KSU_MAX_PACKAGE_NAME);\n'
         '\t\tlist_add_tail(&data->list, &uid_list);\n'
         '\t\t// reset line start\n'
         '\t\tline_start = pos;\n'
         '\t}\n'
         '\tfilp_close(fp, 0);\n'
         '\n'
         '\tif (prune_only) {\n'
         '\t\tpr_info("throne_tracker: prune allowlist only!\\n");\n'
         '\t\tgoto prune;\n'
         '\t}\n'
         '\n'
         '\t// now update uid list\n'
         '\tstruct uid_data *np, *n;\n'
         '\n'
         '\t// first, check if manager_uid exist!\n'
         '\tbool manager_exist = false;\n'
         '\tlist_for_each_entry (np, &uid_list, list) {\n'
         '\t\tif (np->uid == ksu_get_manager_appid()) {\n'
         '\t\t\tmanager_exist = true;\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t}\n'
         '\n'
         '\tif (!manager_exist) {\n'
         '\t\tif (ksu_is_manager_appid_valid()) {\n'
         '\t\t\tpr_info("manager is uninstalled, invalidate it!\\n");\n'
         '\t\t\tksu_invalidate_manager_uid();\n'
         '\t\t\tgoto prune;\n'
         '\t\t}\n'
         '\t\tpr_info("Searching manager...\\n");\n'
         '\t\tsearch_manager("/data/app", 2, &uid_list);\n'
         '\t\tpr_info("Search manager finished.\\n");\n'
         '\t}\n'
         '\n'
         'prune:\n'
         '\t// then prune the allowlist\n'
         '\tksu_prune_allowlist(is_uid_exist, &uid_list);\n'
         'out:\n'
         '\t// free uid_list\n'
         '\tlist_for_each_entry_safe (np, n, &uid_list, list) {\n'
         '\t\tlist_del(&np->list);\n'
         '\t\tkfree(np);\n'
         '\t}\n'
         '}'),
        ('void track_throne(bool prune_only, bool force_search_manager)\n'
         '{\n'
         '\tstruct list_head uid_list;\n'
         '\tstruct uid_data *np, *n;\n'
         '\tstruct file *fp;\n'
         '\tchar chr = 0;\n'
         '\tloff_t pos = 0;\n'
         '\tloff_t line_start = 0;\n'
         '\tchar buf[KSU_MAX_PACKAGE_NAME];\n'
         '\tbool need_search = force_search_manager;\n'
         '\tunsigned long *curr_app_id_map = NULL;\n'
         '\tunsigned long *diff_map = NULL;\n'
         '\n'
         '\tmutex_lock(&app_list_lock);\n'
         '\tif (unlikely(!last_app_id_map))\n'
         '\t\tlast_app_id_map = kcalloc(BITS_TO_LONGS(MAX_APP_ID),\n'
         '\t\t\t\t\t  sizeof(unsigned long), GFP_KERNEL);\n'
         '\tmutex_unlock(&app_list_lock);\n'
         '\n'
         '\tcurr_app_id_map = kcalloc(BITS_TO_LONGS(MAX_APP_ID),\n'
         '\t\t\t\t  sizeof(unsigned long), GFP_KERNEL);\n'
         '\tif (!curr_app_id_map)\n'
         '\t\treturn;\n'
         '\n'
         '\tdiff_map = kcalloc(BITS_TO_LONGS(MAX_APP_ID),\n'
         '\t\t\t   sizeof(unsigned long), GFP_KERNEL);\n'
         '\tif (!diff_map) {\n'
         '\t\tkfree(curr_app_id_map);\n'
         '\t\treturn;\n'
         '\t}\n'
         '\n'
         '\tINIT_LIST_HEAD(&uid_list);\n'
         '\n'
         '\tfp = ksu_filp_open_compat(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);\n'
         '\tif (IS_ERR(fp)) {\n'
         '\t\tpr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\\n",\n'
         '\t\t       __func__, PTR_ERR(fp));\n'
         '\t\tgoto out;\n'
         '\t}\n'
         '\n'
         '\tfor (;;) {\n'
         '\t\tstruct uid_data *data = NULL;\n'
         '\t\tssize_t count =\n'
         '\t\t\tksu_kernel_read_compat(fp, &chr, sizeof(chr), &pos);\n'
         '\t\tconst char *delim = " ";\n'
         '\t\tchar *package = NULL, *tmp = NULL, *uid_str = NULL;\n'
         '\t\tu32 res;\n'
         '\n'
         '\t\tif (count != sizeof(chr))\n'
         '\t\t\tbreak;\n'
         '\t\tif (chr != \'\\n\')\n'
         '\t\t\tcontinue;\n'
         '\n'
         '\t\tcount = ksu_kernel_read_compat(fp, buf, sizeof(buf),\n'
         '\t\t\t\t\t       &line_start);\n'
         '\t\tdata = kzalloc(sizeof(struct uid_data), GFP_ATOMIC);\n'
         '\t\tif (!data) {\n'
         '\t\t\tfilp_close(fp, 0);\n'
         '\t\t\tgoto out;\n'
         '\t\t}\n'
         '\t\ttmp     = buf;\n'
         '\t\tpackage = strsep(&tmp, delim);\n'
         '\t\tuid_str = strsep(&tmp, delim);\n'
         '\t\tif (!uid_str || !package) {\n'
         '\t\t\tpr_err("update_uid: package or uid NULL\\n");\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t\tif (kstrtou32(uid_str, 10, &res)) {\n'
         '\t\t\tpr_err("update_uid: uid parse err\\n");\n'
         '\t\t\tbreak;\n'
         '\t\t}\n'
         '\t\tdata->uid = res;\n'
         '\t\tstrncpy(data->package, package, KSU_MAX_PACKAGE_NAME);\n'
         '\t\tlist_add_tail(&data->list, &uid_list);\n'
         '\t\t{\n'
         '\t\t\tu16 appid = res % PER_USER_RANGE;\n'
         '\t\t\tif (appid >= FIRST_APPLICATION_UID &&\n'
         '\t\t\t    appid < FIRST_APPLICATION_UID + MAX_APP_ID)\n'
         '\t\t\t\tset_bit(appid - FIRST_APPLICATION_UID,\n'
         '\t\t\t\t\tcurr_app_id_map);\n'
         '\t\t}\n'
         '\t\tline_start = pos;\n'
         '\t}\n'
         '\tfilp_close(fp, 0);\n'
         '\n'
         '\tif (prune_only)\n'
         '\t\tgoto prune;\n'
         '\n'
         '\tmutex_lock(&app_list_lock);\n'
         '\tif (last_app_id_map &&\n'
         '\t    bitmap_andnot(diff_map, last_app_id_map, curr_app_id_map,\n'
         '\t\t\t  MAX_APP_ID)) {\n'
         '\t\tint bit = -1;\n'
         '\t\twhile ((bit = find_next_bit(diff_map, MAX_APP_ID,\n'
         '\t\t\t\t\t    bit + 1)) < MAX_APP_ID) {\n'
         '\t\t\tu16 appid = (u16)(bit + FIRST_APPLICATION_UID);\n'
         '\t\t\tif (ksu_is_manager_appid(appid)) {\n'
         '\t\t\t\tpr_info("Manager removed appid=%d\\n", appid);\n'
         '\t\t\t\tksu_unregister_manager(appid);\n'
         '\t\t\t}\n'
         '\t\t}\n'
         '\t}\n'
         '\tif (last_app_id_map &&\n'
         '\t    bitmap_andnot(diff_map, curr_app_id_map, last_app_id_map,\n'
         '\t\t\t  MAX_APP_ID)) {\n'
         '\t\tif (!bitmap_empty(diff_map, MAX_APP_ID))\n'
         '\t\t\tneed_search = true;\n'
         '\t}\n'
         '\tif (last_app_id_map)\n'
         '\t\tbitmap_copy(last_app_id_map, curr_app_id_map, MAX_APP_ID);\n'
         '\tmutex_unlock(&app_list_lock);\n'
         '\n'
         '\tif (need_search) {\n'
         '\t\tpr_info("Searching for manager(s)...\\n");\n'
         '\t\tsearch_manager("/data/app", 2, &uid_list);\n'
         '\t\tpr_info("Manager search finished\\n");\n'
         '\t}\n'
         '\n'
         'prune:\n'
         '\tksu_prune_allowlist(is_uid_exist, &uid_list);\n'
         'out:\n'
         '\tlist_for_each_entry_safe(np, n, &uid_list, list) {\n'
         '\t\tlist_del(&np->list);\n'
         '\t\tkfree(np);\n'
         '\t}\n'
         '\tkfree(curr_app_id_map);\n'
         '\tkfree(diff_map);\n'
         '}'),
        "throne_tracker.c track_throne")

    write(p, c)

    # ------------------------------------------------------------------
    # 12: lsm_hook.c / ksud.c
    # ------------------------------------------------------------------
    print("[12/13] Patching lsm_hook.c")
    for fname in ["lsm_hook.c", "lsm_hooks.c", "ksud.c"]:
        fp = os.path.join(kdir, fname)
        if not os.path.exists(fp):
            continue
        c = read(fp)
        changed = False
        if 'track_throne(true);' in c:
            c = c.replace('track_throne(true);',  'track_throne(true, false);')
            changed = True
        if 'track_throne(false);' in c:
            c = c.replace('track_throne(false);', 'track_throne(false, false);')
            changed = True
        if changed:
            write(fp, c)

    # ------------------------------------------------------------------
    # 13: Kconfig + Makefile
    # ------------------------------------------------------------------
    print("[13/13] Patching Kconfig + Makefile")
    p = os.path.join(kdir, "Kconfig")
    c = read(p)
    if 'KSU_MULTI_MANAGER_SUPPORT' not in c:
        c = patch(c,
            '\nconfig KSU_ALLOWLIST_WORKAROUND\n',
            ('\nconfig KSU_MULTI_MANAGER_SUPPORT\n'
             '\tbool "Multi KernelSU manager support"\n'
             '\tdepends on KSU\n'
             '\tdefault y\n'
             '\thelp\n'
             '\t\tEnable multi KernelSU manager support\n'
             '\nconfig KSU_ALLOWLIST_WORKAROUND\n'),
            "Kconfig")
    write(p, c)

    p = os.path.join(kdir, "Makefile")
    c = read(p)
    if 'dynamic_manager.o' not in c:
        c = patch(c,
            'ksu_obj-y += throne_tracker.o\n',
            ('ksu_obj-y += throne_tracker.o\n'
             'ksu_obj-y += dynamic_manager.o\n'
             'ksu_obj-y += manager.o\n'),
            "Makefile")
    write(p, c)

    print("\n[+] All patches applied successfully.")
    print("    Add CONFIG_KSU_MULTI_MANAGER_SUPPORT=y to your defconfig.\n")

if __name__ == "__main__":
    main()
