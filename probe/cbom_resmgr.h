/*
 * cbom_resmgr.h - serves the probe report as a file at /dev/cbom (QNX resource manager).
 * Included by cbom_probe.c when built with -DCBOM_WITH_RESMGR.
 * A read from offset 0 builds a fresh report; later reads continue in that report.
 * There is one report for all opens, so two readers at the same time can get a mixed
 * report; read it one open at a time. The file is readable by root only because
 * the report lists every process that uses a crypto library.
 */
struct _iofunc_attr;
struct _iofunc_ocb;
#define RESMGR_OCB_T struct _iofunc_ocb  /* typed open-control-block pointer in handlers */
#define RESMGR_HANDLE_T struct _iofunc_attr
#include <sys/dispatch.h>
#include <sys/iofunc.h>

#define CBOM_DEVICE "/dev/cbom"

static struct text snapshot;

static int cbom_read(resmgr_context_t *ctp, io_read_t *msg, iofunc_ocb_t *ocb)
{
    int status = iofunc_read_verify(ctp, msg, ocb, NULL);
    off_t offset = ocb->offset;
    size_t left;
    size_t nbytes;

    if (status != EOK) {
        return status;
    }
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
        return ENOSYS;
    }
    if (offset == 0) {
        text_free(&snapshot);
        if (make_report(-1, &snapshot) != 0) {
            text_free(&snapshot);
            return EIO;
        }
    }
    left = (size_t)offset < snapshot.len ? snapshot.len - (size_t)offset : 0;
    nbytes = msg->i.nbytes < left ? msg->i.nbytes : left;
    _IO_SET_READ_NBYTES(ctp, nbytes);
    if (nbytes == 0) {
        return _RESMGR_NPARTS(0);
    }
    SETIOV(&ctp->iov[0], snapshot.data + offset, nbytes);
    ocb->offset += (off_t)nbytes;
    return _RESMGR_NPARTS(1);
}

static int serve_resmgr(void)
{
    dispatch_t *dpp = dispatch_create();
    resmgr_attr_t rattr;
    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    iofunc_attr_t attr;
    dispatch_context_t *ctp;

    if (dpp == NULL) {
        fprintf(stderr, "cbom_probe: dispatch_create failed: errno %d\n", errno);
        return 1;
    }
    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.read = cbom_read;
    iofunc_attr_init(&attr, S_IFNAM | 0400, NULL, NULL);
    if (resmgr_attach(dpp, &rattr, CBOM_DEVICE, _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &attr) == -1) {
        fprintf(stderr, "cbom_probe: cannot attach %s: errno %d\n", CBOM_DEVICE, errno);
        return 1;
    }
    ctp = dispatch_context_alloc(dpp);
    if (ctp == NULL) {
        return 1;
    }
    for (;;) {
        if ((ctp = dispatch_block(ctp)) == NULL) {
            fprintf(stderr, "cbom_probe: dispatch_block failed: errno %d\n", errno);
            return 1;
        }
        dispatch_handler(ctp);
    }
}
