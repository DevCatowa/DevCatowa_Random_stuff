with open('drivers/gpu/drm/sprd/sprd_drm.c', 'r') as f:
    content = f.read()

# Add include
old_inc = '#include <drm/drm_gem_framebuffer_helper.h>'
new_inc = '#include <drm/drm_gem_framebuffer_helper.h>\n#include <drm/drm_fb_helper.h>'
content = content.replace(old_inc, new_inc, 1)

# Add fbdev setup after drm_dev_register block
old_code = '''        err = drm_dev_register(drm, 0);
        if (err < 0)
                goto err_kms_helper_poll_fini;

        /* initialize kworker & kwork and create kthread */'''

new_code = '''        err = drm_dev_register(drm, 0);
        if (err < 0)
                goto err_kms_helper_poll_fini;

        drm_fbdev_generic_setup(drm, 32);

        /* initialize kworker & kwork and create kthread */'''

content = content.replace(old_code, new_code, 1)

with open('drivers/gpu/drm/sprd/sprd_drm.c', 'w') as f:
    f.write(content)

print("Done")
