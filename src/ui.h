#ifndef UI_H
#define UI_H

#include <gtk/gtk.h>
#include "parser.h"

#define MAX_PORT_ALLOWED 65535

#define WINDOW_WIDTH 700
#define WINDOW_HEIGHT 500

#define root_append(widget) gtk_box_append(GTK_BOX(rootBox), widget)
#define box_append(box, widget) gtk_box_append(GTK_BOX(box), widget)

#define entry_get_text(entry) gtk_entry_buffer_get_text(gtk_entry_get_buffer(entry))

void ui_activate(GtkApplication* app);
void ui_load_rules();

#endif /* ifndef UI_H */
