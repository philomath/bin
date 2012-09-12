/* simple/suckless lock, based on http://hg.suckless.org/slock/ . */

#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/types.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

typedef struct
{
    Window root, win;
    int screen;
} Lock;

static Lock **locks;
static int nscreens;

noreturn static void die(const char *errstr);
static const char *getpw(void);
static Lock *lockscreen(Display *dpy, int screen);
static void readpw(Display *dpy, const char *pws);
static void unlockscreen(Display *dpy, Lock *lock);

int
main(int argc, char *argv[])
{
    const char *pws;
    Display *dpy;

    if ((argc == 2) && (strcmp("-v", argv[1]) == 0))
        die("slock-mod, © 2006-2012 Anselm R Garbe, 2012 philomath\n");
    else if (argc != 1)
        die("usage: slock [-v]\n");

    pws = getpw();

    if ((dpy = XOpenDisplay(NULL)) == NULL)
        die("slock: cannot open display\n");

    /* Get the number of screens in display "dpy" and blank them all. */
    nscreens = ScreenCount(dpy);
    locks = malloc(sizeof(Lock *) * nscreens);

    if (locks == NULL)
        die("slock: malloc failed\n");

    int nlocks = 0;

    for (int i = 0; i < nscreens; ++i)
    {
        if ((locks[i] = lockscreen(dpy, i)) != NULL)
            nlocks++;
    }

    /* Did we actually manage to lock something? */
    if (nlocks == 0)   // nothing to protect
    {
        free(locks);
        XCloseDisplay(dpy);
        die("cannot lock anything\n");
    }

    /* Everything is now blank. Now wait for the correct password. */
    readpw(dpy, pws);

    /* Password ok, unlock everything and quit. */
    for (int i = 0; i < nscreens; ++i)
        unlockscreen(dpy, locks[i]);

    free(locks);
    XCloseDisplay(dpy);
    return 0;
}

noreturn static void
die(const char *errstr)
{
    fputs(errstr, stderr);
    exit(EXIT_FAILURE);
}

static const char *
getpw(void)
{
    const char *rval;
    struct passwd *pw;
    pw = getpwuid(getuid());

    if (pw == NULL)
        die("slock: cannot retrieve password entry\n"
            "(make sure to setcap CAP_DAC_READ_SEARCH+ep)\n");

    endpwent();

    if (pw->pw_passwd[0] != '\0')        /* there is a placeholder */
    {
        struct spwd *sp;
        sp = getspnam(pw->pw_name);

        if (sp == NULL)
            die("slock: cannot retrieve shadow entry\n"
                "(make sure to setcap CAP_DAC_READ_SEARCH+ep)\n");

        endspent();
        rval = sp->sp_pwdp;
    }
    else
        rval =  pw->pw_passwd;

    return rval;
}

static Lock *
lockscreen(Display *dpy, int screen)     /* Here is the meat */
{
    int count;
    Lock *lock;
    XSetWindowAttributes wa;

    if (dpy == NULL || screen < 0)
        return NULL;

    lock = malloc(sizeof(Lock));

    if (lock == NULL)
        return NULL;

    lock->screen = screen;
    lock->root = RootWindow(dpy, lock->screen);
    /* init */
    wa.override_redirect = true;
    wa.background_pixel = BlackPixel(dpy, lock->screen);
    lock->win = XCreateWindow(dpy, lock->root, 0, 0, DisplayWidth(dpy, lock->screen), DisplayHeight(dpy, lock->screen),
                              0, DefaultDepth(dpy, lock->screen), CopyFromParent,
                              DefaultVisual(dpy, lock->screen), CWOverrideRedirect | CWBackPixel, &wa);
    XMapRaised(dpy, lock->win);

    for (count = 0; count < 10000; ++count)
    {
        if (XGrabPointer(dpy, lock->root, False, ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
                         GrabModeAsync, GrabModeAsync, None, None, CurrentTime) == GrabSuccess)
            break;
    }

    if (count < 10000)
    {
        for (count = 0; count < 10000; ++count)
        {
            if (XGrabKeyboard(dpy, lock->root, True, GrabModeAsync, GrabModeAsync, CurrentTime)
                    == GrabSuccess)
                break;
        }
    }

    if (count >= 10000)  // timed out
    {
        unlockscreen(dpy, lock);
        lock = NULL;
    }
    else
        XSelectInput(dpy, lock->root, SubstructureNotifyMask);

    return lock;
}

static void
readpw(Display *dpy, const char *pws)
{
    char buf[32], pass[256];
    int num, screen;
    int len = 0;
    KeySym ksym;
    XEvent ev;
    bool running = true;

    /* As "slock" stands for "Simple X display locker", the DPMS settings
     * had been removed and you can set it with "xset" or some other
     * utility. This way the user can easily set a customized DPMS
     * timeout. */
    while (running && (XNextEvent(dpy, &ev) == 0))
    {
        if (ev.type == KeyPress)
        {
            buf[0] = 0;
            num = XLookupString(&ev.xkey, buf, sizeof buf, &ksym, NULL);

            if (IsKeypadKey(ksym))
            {
                if (ksym == XK_KP_Enter)
                    ksym = XK_Return;
                else if (ksym >= XK_KP_0 && ksym <= XK_KP_9)
                    ksym = (ksym - XK_KP_0) + XK_0;
            }

            if (IsFunctionKey(ksym) || IsKeypadKey(ksym)
                    || IsMiscFunctionKey(ksym) || IsPFKey(ksym)
                    || IsPrivateKeypadKey(ksym))
                continue;

            switch (ksym)
            {
                case XK_Return:
                    pass[len] = 0;
                    running = strcmp(crypt(pass, pws), pws);

                    if (running)
                        XBell(dpy, 100);  // wrong password!

                    len = 0;
                    break;

                case XK_Escape:
                    len = 0;
                    break;

                case XK_BackSpace:
                    if (len)
                        --len;
                    break;

                default:
                    if (num && !iscntrl((int) buf[0]) && (len + num < sizeof pass))
                    {
                        memcpy(pass + len, buf, num);
                        len += num;
                    }
                    break;
            }
        }
        else for (screen = 0; screen < nscreens; screen++)
                XRaiseWindow(dpy, locks[screen]->win);
    }
}

static void
unlockscreen(Display *dpy, Lock *lock)
{
    if (dpy == NULL || lock == NULL)
        return;

    XUngrabPointer(dpy, CurrentTime);
    XDestroyWindow(dpy, lock->win);
    free(lock);
}
