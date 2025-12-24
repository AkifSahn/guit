#include <gtk/gtk.h>
#include <stdlib.h>

#include "parser.c"

#define WINDOW_WIDTH 700
#define WINDOW_HEIGHT 500

static GtkWidget* rootBox;
static GtkWidget* window;
static GtkWidget* rules_box;

static GtkSizeGroup* sg_num;
static GtkSizeGroup* sg_pkts;
static GtkSizeGroup* sg_prot;
static GtkSizeGroup* sg_target;
static GtkSizeGroup* sg_src;
static GtkSizeGroup* sg_dst;

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

    gtk_widget_set_hexpand(inputButton, TRUE);
    gtk_widget_set_hexpand(outputButton, TRUE);
    gtk_widget_set_hexpand(forwardButton, TRUE);

    box_append(button_row, inputButton);
    box_append(button_row, outputButton);
    box_append(button_row, forwardButton);

    box_append(topPanel, label_row);
    box_append(topPanel, button_row);
}

void box_clear_children(GtkWidget *parent){
    if (!parent) {
        LOG("NULL parent!");
        exit(1);
    }

    GtkWidget* cur;
    GtkWidget* next;
    cur = gtk_widget_get_first_child(parent);
    while (cur) {
        next = gtk_widget_get_next_sibling(cur);
        gtk_box_remove(GTK_BOX(parent), cur);
        cur = next;
    }
}

void init_rules_box_size_groups(){
    sg_num = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_pkts = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_prot = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_target = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_src = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_dst = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
}

GtkWidget* make_rules_info_header(){
    GtkWidget *w_num, *w_pkts, *w_prot, *w_target, *w_src, *w_dst, *w_seperator;
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    w_num = gtk_label_new("num");

    w_pkts = gtk_label_new("pkts");
    w_prot = gtk_label_new("prot");
    w_target = gtk_label_new("target");
    w_src = gtk_label_new("src");
    w_dst = gtk_label_new("dst");

    // gtk_widget_set_hexpand(w_num, TRUE);
    gtk_widget_set_hexpand(w_pkts, TRUE);
    gtk_widget_set_hexpand(w_prot, TRUE);
    gtk_widget_set_hexpand(w_target, TRUE);
    gtk_widget_set_hexpand(w_src, TRUE);
    gtk_widget_set_hexpand(w_dst, TRUE);

    gtk_size_group_add_widget(sg_num, w_num);
    gtk_size_group_add_widget(sg_pkts, w_pkts);
    gtk_size_group_add_widget(sg_prot, w_prot);
    gtk_size_group_add_widget(sg_target, w_target);
    gtk_size_group_add_widget(sg_src, w_src);
    gtk_size_group_add_widget(sg_dst, w_dst);

    box_append(box, w_num);
    box_append(box, w_pkts);
    box_append(box, w_prot);
    box_append(box, w_target);
    box_append(box, w_src);
    box_append(box, w_dst);

    return box;
}

GtkWidget* make_rule_box(const Rule rule){
    GtkWidget *w_num, *w_pkts, *w_prot, *w_target, *w_src, *w_dst, *w_seperator;
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_add_css_class(box, "rule-box");

    char str_buffer[1024];

    snprintf(str_buffer, sizeof(str_buffer), "%d.",rule.num);
    w_num = gtk_label_new(str_buffer);
    snprintf(str_buffer, sizeof(str_buffer), "%d",rule.pkts);
    w_pkts = gtk_label_new(str_buffer);

    w_prot = gtk_label_new(rule.prot);
    w_target = gtk_label_new(rule.target);
    w_src = gtk_label_new(rule.src);
    w_dst = gtk_label_new(rule.dst);

    w_seperator = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

    // gtk_widget_set_hexpand(w_num, TRUE);
    gtk_widget_set_hexpand(w_pkts, TRUE);
    gtk_widget_set_hexpand(w_prot, TRUE);
    gtk_widget_set_hexpand(w_target, TRUE);
    gtk_widget_set_hexpand(w_src, TRUE);
    gtk_widget_set_hexpand(w_dst, TRUE);

    gtk_size_group_add_widget(sg_num, w_num);
    gtk_size_group_add_widget(sg_pkts, w_pkts);
    gtk_size_group_add_widget(sg_prot, w_prot);
    gtk_size_group_add_widget(sg_target, w_target);
    gtk_size_group_add_widget(sg_src, w_src);
    gtk_size_group_add_widget(sg_dst, w_dst);

    box_append(box, w_num);
    box_append(box, w_pkts);
    box_append(box, w_prot);
    box_append(box, w_target);
    box_append(box, w_src);
    box_append(box, w_dst);

    box_append(rules_box, w_seperator);

    return box;
}

void load_rules(){
    Rules rules = {0};
    sudo_cmd("iptables -L INPUT -vn --line-numbers > tables.tmp");
    box_clear_children(rules_box); // Clear the box
    box_append(rules_box, make_rules_info_header());
    if (!parse_rules_from_file("tables.tmp", &rules)){
        for (int i = 0;  i < rules.count; i++) {
            box_append(rules_box, make_rule_box(rules.items[i]));
        }
    }
}

void populate_rule_listing_box(){
    GtkWidget *scrolled_window = gtk_scrolled_window_new();

    rules_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);


    gtk_widget_add_css_class(rules_box, "rules-box");

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), rules_box);
    gtk_widget_set_vexpand(scrolled_window, TRUE);

    init_rules_box_size_groups();
    load_rules();
    root_append(scrolled_window);
}

void populate_bottom_panel(){
    // Buttons
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_add_css_class(panel, "bottom-panel");

    GtkWidget *add_rule_btn = gtk_button_new_with_label("Add Rule +");
    GtkWidget *refresh_btn = gtk_button_new_with_label("Refresh 🗘");
    
    g_signal_connect(GTK_BUTTON(refresh_btn), "clicked", G_CALLBACK(load_rules), NULL);

    box_append(panel, add_rule_btn);
    box_append(panel, refresh_btn);

    root_append(panel);
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
    populate_rule_listing_box();
    populate_bottom_panel();

    load_css();

    gtk_window_present(GTK_WINDOW(window));
}

int main(int argc, char **argv) {
    GtkApplication* app;
    int status;

    app = gtk_application_new("gui.iptables", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK (activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref (app);
    
    return status;
}
