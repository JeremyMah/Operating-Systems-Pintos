#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#define MAX_FD 128
static void syscall_handler (struct intr_frame *);
//Array of open files with arbitrarily large size (as allowed by documentation).
static struct file *files[MAX_FD];

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  int i;
  for (i = 0; i < MAX_FD; i++)
    files[i] = NULL;
}

//Exits the process with the given status.
void
syscall_exit (struct intr_frame *f, int status)
{
  f->eax = status;
  thread_current ()->return_status = status;
  printf ("%s: exit(%d)\n", thread_name (), status);
  thread_exit ();
}

//Returns true if the pointer is bad, false otherwise.
bool
bad_ptr (void *ptr)
{
  return ptr == NULL || is_kernel_vaddr (ptr)
    || pagedir_get_page (thread_current ()->pagedir, ptr) == NULL;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //Gets the system call number from the stack pointer.
  uint32_t *syscall = f->esp;

  /* Exits  with -1 if the stack pointer is under the code segment
   * or just below PHYS_BASE. */
  if (is_kernel_vaddr (syscall + 4)
      || pagedir_get_page (thread_current ()->pagedir, syscall) == NULL)
    syscall_exit (f, -1);

  switch (*syscall)
  {
    case SYS_HALT:
      //Shuts down the OS.
      shutdown_power_off ();
      break;
    case SYS_EXIT:
    {
      //Exits with the given status.
      int status = *(syscall + 1);
      syscall_exit (f, status);
      break;
    }
    case SYS_EXEC:
    {
      //Executes the given command.
      const char *cmd_line = *(syscall + 1);
      if (bad_ptr (cmd_line))
        syscall_exit (f, -1);
      f->eax = process_execute (cmd_line);
      break;
    }
    case SYS_WAIT:
    {
      //Waits for the process corresponding to the given pid.
      int pid = *(syscall + 1);
      f->eax = process_wait (pid);
      break;
    }
    case SYS_CREATE:
    {
      //Creates a file with the given filename and size.
      const char *filename = *(syscall + 1);
      unsigned size = *(syscall + 2);
      if (bad_ptr (filename))
        syscall_exit (f, -1);
      f->eax = strlen (filename) > 0 ? filesys_create (filename, size) : 0;
      break;
    }
    case SYS_REMOVE:
    {
      //Removes the file with the given filename.
      const char *filename = *(syscall + 1);
      if (bad_ptr (filename))
        syscall_exit (f, -1);
      f->eax = filesys_remove (filename);
      break;
    }
    case SYS_OPEN:
    {
      //Opens the file with the given filename.
      const char *filename = *(syscall + 1);
      if (bad_ptr (filename))
        syscall_exit (f, -1);
      struct file *open_file = filesys_open (filename);
      int fd;
      f->eax = -1;
      if (open_file != NULL)
      {
        for (fd = 2; fd < MAX_FD + 2; fd++)
        {
          if (files[fd - 2] == NULL)
          {
            //Returns an available file descriptor for the file.
            files[fd - 2] = open_file;
            f->eax = fd;
            break;
          }
        }
      }
      break;
    }
    case SYS_FILESIZE:
    {
      //Returns the size of the file corresponding to the given descriptor.
      int fd = *(syscall + 1);
      if (fd > STDOUT_FILENO && fd < MAX_FD + 2 && files[fd - 2] != NULL)
       f->eax = file_length (files[fd - 2]);
      else
        f->eax = 0;
      break;
    }
    case SYS_READ:
    {
      /* Reads the file corresponding to fd and places up to size characters
       * in buffer. */
      int fd = *(syscall + 1);
      void *buffer = (void *) *(syscall + 2);
      unsigned size = *(syscall + 3);
      if (bad_ptr (buffer))
        syscall_exit (f, -1);
      if (fd != STDOUT_FILENO && fd < MAX_FD + 2 && files[fd - 2] != NULL)
        f->eax = file_read (files[fd - 2], buffer, size);
      else
        f->eax = -1;
      break;
    }
    case SYS_WRITE:
    {
      /* Writes up to size characters from buffer to the file corresponding to
       * fd. */
      int fd = *(syscall + 1);
      void *buffer = (void *) *(syscall + 2);
      int size = *(int *) (syscall + 3);
      if (bad_ptr (buffer))
        syscall_exit (f, -1);
      if (fd == STDOUT_FILENO)
      {
        //Writes to stdout if its file descriptor was given.
        putbuf ((char *) buffer, size);
        f->eax = size;
      }
      else if (fd > STDOUT_FILENO && fd < MAX_FD + 2 && files[fd - 2] != NULL)
        f->eax = file_write (files[fd - 2], buffer, size);
      break;
    }
    case SYS_SEEK:
    {
      //Sets the position within the file corresponding to fd to position.
      int fd = *(syscall + 1);
      unsigned position = *(syscall + 2);
      if (fd > STDOUT_FILENO && fd < MAX_FD + 2 && files[fd - 2] != NULL)
        file_seek (files[fd - 2], position);
      break;
    }
    case SYS_TELL:
    {
      //Returns the position within the file corresponding to the given fd.
      int fd = *(syscall + 1);
      if (fd > STDOUT_FILENO && fd < MAX_FD + 2 && files[fd - 2] != NULL)
        f->eax = file_tell (files[fd - 2]);
      break;
    }
    case SYS_CLOSE:
    {
      //Closes the file corresponding to the given fd.
      int fd = *(syscall + 1);
      if (fd != STDOUT_FILENO && fd != STDIN_FILENO && fd < MAX_FD + 2
          && files[fd - 2] != NULL)
      {
        file_close (files[fd - 2]);
        //Frees the closed file's index so it may be used for another file.
        files[fd - 2] = NULL;
      }
      break;
    }
  }
}
