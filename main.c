#include <gtk/gtk.h>

#define WINDOW_WIDTH 700
#define WINDOW_HEIGHT 500

GtkWidget* rootBox;
GtkWidget* window;

#define root_append(widget) gtk_box_append(GTK_BOX(rootBox), widget)
#define box_append(box, widget) gtk_box_append(GTK_BOX(box), widget)

void load_css(){
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(
            provider,
            "./style.css"
            );

    gtk_style_context_add_provider_for_display(
            gtk_widget_get_display(window),
            GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
            );
}

void populate_top_panel(){
    // Populate Top Panel
    GtkWidget* topPanel;
    topPanel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_add_css_class(topPanel, "top-panel");
    gtk_widget_set_hexpand(topPanel, TRUE);
    root_append(topPanel);

    // Label
    GtkWidget* label_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(label_row, TRUE);
    gtk_widget_set_halign(label_row, GTK_ALIGN_CENTER);

    GtkWidget *label = gtk_label_new("Chains");
    box_append(label_row, label);
    
    // Buttons
    GtkWidget *button_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_hexpand(button_row, TRUE);

    GtkWidget *inputButton = gtk_button_new_with_label("Input");
    GtkWidget *outputButton = gtk_button_new_with_label("output");
    GtkWidget *forwardButton = gtk_button_new_with_label("forward");

    gtk_widget_add_css_class(inputButton, "top-panel-button");
    gtk_widget_set_hexpand(inputButton, TRUE);
    gtk_widget_add_css_class(outputButton, "top-panel-button");
    gtk_widget_set_hexpand(outputButton, TRUE);
    gtk_widget_add_css_class(forwardButton, "top-panel-button");
    gtk_widget_set_hexpand(forwardButton, TRUE);

    box_append(button_row, inputButton);
    box_append(button_row, outputButton);
    box_append(button_row, forwardButton);

    box_append(topPanel, label_row);
    box_append(topPanel, button_row);
}

void activate(GtkApplication*app, gpointer user_data){

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "iptables");
    gtk_window_set_default_size(GTK_WINDOW(window), WINDOW_WIDTH, WINDOW_HEIGHT);

    // Add root box
    rootBox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_hexpand(rootBox, TRUE);
    gtk_widget_add_css_class(window, "root");
    gtk_window_set_child(GTK_WINDOW(window), rootBox);

    populate_top_panel();

    load_css();

    gtk_window_present(GTK_WINDOW(window));
}

#define do_cmd(cmd)\
    do{\
        if(system(cmd)){\
            fprintf(stderr, "do_cmd");\
            return 1;\
        }\
    }while(0)

#define sudo_cmd(cmd) do_cmd("sudo " cmd)

int main(int argc, char **argv) {
    GtkApplication* app;
    int status;

    app = gtk_application_new("gui.iptables", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK (activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref (app);
    
    return status;
}
