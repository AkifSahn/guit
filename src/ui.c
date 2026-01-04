#include "ui.h"
#include "ipt.h"

#define INPUT_POPUP_WIDTH 900
#define INPUT_POPUP_HEIGHT 150

#define INSERT_IP_POPUP_WIDTH 500
#define INSERT_IP_POPUP_HEIGHT 150

// Global variables
typedef struct{
    GtkWidget* window;
    GtkWidget* root_box;
    GtkWidget* rules_box;

    Rules rules;
}AppState;

static AppState state = {0};

static GtkSizeGroup* sg_num;
static GtkSizeGroup* sg_pkts;
static GtkSizeGroup* sg_prot;
static GtkSizeGroup* sg_target;
static GtkSizeGroup* sg_src;
static GtkSizeGroup* sg_dst;
static GtkSizeGroup* sg_spt;
static GtkSizeGroup* sg_dpt;
static GtkSizeGroup* sg_actions;

typedef struct{
    GtkWidget *window;
    GtkWidget *sb_num;
    GtkWidget *dd_prot;
    GtkWidget *dd_target;
    GtkWidget *e_src;
    GtkWidget *e_dst;
    GtkWidget *sb_spt;
    GtkWidget *sb_dpt;

    // If > 0, we are editing this specific rule number
    int editing_rule_num;
}InputWidgets;

static const char* dd_prot_options[] = {"all", "tcp", "udp", NULL};
static const char* dd_target_options[] = {"ACCEPT", "REJECT", "DROP", NULL};

int get_dropdown_index(const char** options, const char* target) {
    if (!target) return 0;
    for (int i = 0; options[i] != NULL; i++) {
        if (strcmp(options[i], target) == 0) return i;
    }
    return 0; // Default to first if not found
}

void load_css(){
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_path(
            provider,
            "./src/style.css"
            );

    gtk_style_context_add_provider_for_display(
            gtk_widget_get_display(state.window),
            GTK_STYLE_PROVIDER(provider),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
            );
}

void init_rules_box_size_groups(){
    sg_num = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_pkts = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_prot = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_target = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_src = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_dst = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_spt = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_dpt = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    sg_actions = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
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

void populate_top_panel(){
    // Populate Top Panel
    GtkWidget* topPanel;
    topPanel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_add_css_class(topPanel, "top-panel");
    gtk_widget_set_hexpand(topPanel, TRUE);
    root_append(state, topPanel);

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
    GtkWidget *outputButton = gtk_button_new_with_label("Whitelist");
    GtkWidget *forwardButton = gtk_button_new_with_label("Blacklist");

    gtk_widget_set_hexpand(inputButton, TRUE);
    gtk_widget_set_hexpand(outputButton, TRUE);
    gtk_widget_set_hexpand(forwardButton, TRUE);

    box_append(button_row, inputButton);
    box_append(button_row, outputButton);
    box_append(button_row, forwardButton);

    box_append(topPanel, label_row);
    box_append(topPanel, button_row);
}

void populate_rule_listing_box(){
    GtkWidget *scrolled_window = gtk_scrolled_window_new();

    state.rules_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);


    gtk_widget_add_css_class(state.rules_box, "rules-box");

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled_window), state.rules_box);
    gtk_widget_set_vexpand(scrolled_window, TRUE);

    init_rules_box_size_groups();
    ui_load_rules();
    root_append(state, scrolled_window);
}

void query_new_rule(GtkButton* btn, void* data){
    InputWidgets widgets = *(InputWidgets*)data;

    bool run_cmd = true;
    int num, spt, dpt;
    char *src, *dst;
    const char *prot, *target;

    num = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widgets.sb_num));
    spt = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widgets.sb_spt));
    dpt = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(widgets.sb_dpt));

    int sel;
    sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(widgets.dd_prot));
    prot = dd_prot_options[sel];
    sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(widgets.dd_target));
    target = dd_target_options[sel];

    src = strdup(entry_get_text(GTK_ENTRY(widgets.e_src)));
    dst = strdup(entry_get_text(GTK_ENTRY(widgets.e_dst)));
    str_trim(src);
    str_trim(dst);

    if (*src){
        if (gtk_widget_has_css_class(widgets.e_src, "error-entry"))
            gtk_widget_remove_css_class(widgets.e_src, "error-entry");

        if (!is_valid_ipv4_or_cidr(src)) {
            run_cmd = false;
            gtk_widget_add_css_class(widgets.e_src, "error-entry");
        }
    }

    if (*dst){
        if (gtk_widget_has_css_class(widgets.e_dst, "error-entry"))
            gtk_widget_remove_css_class(widgets.e_dst, "error-entry");

        if (!is_valid_ipv4_or_cidr(dst)) {
            run_cmd = false;
            gtk_widget_add_css_class(widgets.e_dst, "error-entry");
        }
    }

    if (run_cmd){
        if (widgets.editing_rule_num > 0) {
            ipt_replace_rule(widgets.editing_rule_num, src, dst, prot, spt, dpt, target);
        }else{
            ipt_insert_new_rule(num, src, dst, prot, spt, dpt, target);
        }
        gtk_window_destroy(GTK_WINDOW(widgets.window));
        ui_load_rules();
    }
    free(src);
    free(dst);
    g_free(data);
}

// If rule_to_edit is NULL -> Add Mode
// If rule_to_edit is set -> Edit Mode
void popup_rule_window(const Rule* rule_to_edit){
    GtkWidget* window = gtk_window_new();
    gtk_window_set_resizable(GTK_WINDOW(window), false);
    gtk_window_set_default_size(GTK_WINDOW(window), INPUT_POPUP_WIDTH, INPUT_POPUP_HEIGHT);

    if (rule_to_edit) {
        gtk_window_set_title(GTK_WINDOW(window), "Edit Rule");
    }else{
        gtk_window_set_title(GTK_WINDOW(window), "Add Rule");
    }

    GtkWidget *root_box, *input_box, *label_box;
    root_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(root_box, GTK_ALIGN_CENTER);
    gtk_widget_set_hexpand(state.root_box, TRUE);
    gtk_widget_add_css_class(window, "root");
    gtk_window_set_child(GTK_WINDOW(window), root_box);

    GtkSizeGroup* sg_num = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    GtkSizeGroup* sg_prot = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    GtkSizeGroup* sg_target = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    GtkSizeGroup* sg_src = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    GtkSizeGroup* sg_dst = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    GtkSizeGroup* sg_spt = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);
    GtkSizeGroup* sg_dpt = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);

    // Label Box
    {
        GtkWidget *l_num, *l_prot, *l_target, *l_src,
                  *l_dst, *l_spt, *l_dpt, *w_separator;

        label_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
        gtk_widget_add_css_class(label_box, "popup-label-box");

        l_num = gtk_label_new("num");
        l_prot = gtk_label_new("prot");
        l_target = gtk_label_new("target");
        l_src = gtk_label_new("src");
        l_dst = gtk_label_new("dst");
        l_spt = gtk_label_new("spt");
        l_dpt = gtk_label_new("dpt");
        w_separator = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

        gtk_size_group_add_widget(sg_num, l_num);
        gtk_size_group_add_widget(sg_prot, l_prot);
        gtk_size_group_add_widget(sg_target, l_target);
        gtk_size_group_add_widget(sg_src, l_src);
        gtk_size_group_add_widget(sg_dst, l_dst);
        gtk_size_group_add_widget(sg_spt, l_spt);
        gtk_size_group_add_widget(sg_dpt, l_dpt);

        box_append(root_box, label_box);
        box_append(label_box, l_num);
        box_append(label_box, l_prot);
        box_append(label_box, l_target);
        box_append(label_box, l_src);
        box_append(label_box, l_dst);
        box_append(label_box, l_spt);
        box_append(label_box, l_dpt);
        box_append(root_box, w_separator);
    }

    // Input Box
    GtkWidget *sb_num, *dd_prot, *dd_target, *e_src, *e_dst, *sb_spt, *sb_dpt;
    GtkAdjustment *num_adjustment, *spt_adjustment, *dpt_adjustment;

    input_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_add_css_class(input_box, "popup-input-box");

    num_adjustment = gtk_adjustment_new (1, 1, state.rules.count+1, 1, 5, 0);
    sb_num = gtk_spin_button_new(num_adjustment, 1, 0);
    if (rule_to_edit) {
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(sb_num), rule_to_edit->num);
        // Usually, when editing, you don't change the number, so maybe disable it?
        // gtk_widget_set_sensitive(sb_num, false); 
    } else {
        // Default to appending (count + 1)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(sb_num), state.rules.count + 1);
    }

    dd_prot = gtk_drop_down_new_from_strings(dd_prot_options);
    if (rule_to_edit && rule_to_edit->prot) {
        gtk_drop_down_set_selected(GTK_DROP_DOWN(dd_prot), 
            get_dropdown_index(dd_prot_options, rule_to_edit->prot));
    }

    dd_target = gtk_drop_down_new_from_strings(dd_target_options);
    if (rule_to_edit && rule_to_edit->target) {
        gtk_drop_down_set_selected(GTK_DROP_DOWN(dd_target), 
            get_dropdown_index(dd_target_options, rule_to_edit->target));
    }

    GtkEntryBuffer* e_src_buff = gtk_entry_buffer_new(NULL, -1);
    if (rule_to_edit && rule_to_edit->src) 
        gtk_entry_buffer_set_text(e_src_buff, rule_to_edit->src, -1);

    GtkEntryBuffer* e_dst_buff = gtk_entry_buffer_new(NULL, -1);
    if (rule_to_edit && rule_to_edit->dst) 
        gtk_entry_buffer_set_text(e_dst_buff, rule_to_edit->dst, -1);

    e_src = gtk_entry_new_with_buffer(e_src_buff);
    e_dst = gtk_entry_new_with_buffer(e_dst_buff);

    spt_adjustment = gtk_adjustment_new (-1, -1, MAX_PORT_ALLOWED, 1, 10, 0);
    sb_spt = gtk_spin_button_new(spt_adjustment, 1, 0);
    if (rule_to_edit) gtk_spin_button_set_value(GTK_SPIN_BUTTON(sb_spt), rule_to_edit->sport);

    dpt_adjustment = gtk_adjustment_new (-1, -1, MAX_PORT_ALLOWED, 1, 10, 0);
    sb_dpt = gtk_spin_button_new(dpt_adjustment, 1, 0);
    if (rule_to_edit) gtk_spin_button_set_value(GTK_SPIN_BUTTON(sb_dpt), rule_to_edit->dport);

    gtk_size_group_add_widget(sg_num, sb_num);
    gtk_size_group_add_widget(sg_prot, dd_prot);
    gtk_size_group_add_widget(sg_target, dd_target);
    gtk_size_group_add_widget(sg_src, e_src);
    gtk_size_group_add_widget(sg_dst, e_dst);
    gtk_size_group_add_widget(sg_spt, sb_spt);
    gtk_size_group_add_widget(sg_dpt, sb_dpt);

    gtk_widget_add_css_class(sb_num, "input-widget");
    gtk_widget_add_css_class(dd_prot, "input-widget");
    gtk_widget_add_css_class(dd_target, "input-widget");
    gtk_widget_add_css_class(e_src, "input-widget");
    gtk_widget_add_css_class(e_dst, "input-widget");
    gtk_widget_add_css_class(sb_spt, "input-widget");
    gtk_widget_add_css_class(sb_dpt, "input-widget");

    box_append(root_box, input_box);

    box_append(input_box, sb_num);
    box_append(input_box, dd_prot);
    box_append(input_box, dd_target);
    box_append(input_box, e_src);
    box_append(input_box, e_dst);
    box_append(input_box, sb_spt);
    box_append(input_box, sb_dpt);
    

    GtkWidget* btn_submit = gtk_button_new_with_label(rule_to_edit ? "Save Changes" : "Add Rule");
    gtk_widget_set_halign(btn_submit, GTK_ALIGN_END);
    gtk_widget_set_margin_end(btn_submit, 12);

    // TODO: gfree
    InputWidgets* widgets = g_new(InputWidgets, 1);

    widgets->window = window;
    widgets->sb_num = sb_num;
    widgets->dd_prot = dd_prot;
    widgets->dd_target = dd_target;
    widgets->e_src = e_src;
    widgets->e_dst = e_dst;
    widgets->sb_spt = sb_spt;
    widgets->sb_dpt = sb_dpt;

    widgets->editing_rule_num = rule_to_edit ? rule_to_edit->num : 0;

    g_signal_connect(GTK_BUTTON(btn_submit), "clicked", G_CALLBACK(query_new_rule), widgets);

    box_append(root_box, btn_submit);

    gtk_window_present(GTK_WINDOW(window));
}

void on_delete_rule(GtkWidget* btn, gpointer data) {
    int rule_num = GPOINTER_TO_INT(data);
    ipt_delete_rule(rule_num); 
    ui_load_rules();
    
    g_print("Deleted rule #%d\n", rule_num);
}

void on_edit_rule(GtkWidget* btn, gpointer data) {
    int rule_num = GPOINTER_TO_INT(data);

    // Find the rule in our global 'rules' array
    Rule* found_rule = NULL;
    for(size_t i = 0; i < state.rules.count; i++){
        if(state.rules.items[i].num == rule_num){
            found_rule = &state.rules.items[i];
            break;
        }
    }

    if(found_rule){
        popup_rule_window(found_rule);
    } else {
        g_printerr("Error: Could not find rule #%d to edit\n", rule_num);
    }
}

void on_add_rule_clicked(GtkWidget* btn, gpointer data){
    popup_rule_window(NULL);
}

void query_insert_ips(GtkButton* self, void* data){
    const char* label = gtk_button_get_label(self);
    const char* ips = entry_get_text((GTK_ENTRY(data)));

    GtkWidget* window = gtk_widget_get_ancestor(GTK_WIDGET(data), GTK_TYPE_WINDOW);

    if (!strcmp(label, "whitelist")) {
        ipt_whitelist_ips(ips);
    }else{
        ipt_blacklist_ips(ips);
    }

    ui_load_rules();
    gtk_window_destroy(GTK_WINDOW(window));
}

void bulk_insert_ip(){
    GtkWidget* window = gtk_window_new();
    gtk_window_set_resizable(GTK_WINDOW(window), false);
    gtk_window_set_default_size(GTK_WINDOW(window), INSERT_IP_POPUP_WIDTH, INSERT_IP_POPUP_HEIGHT);

    GtkWidget *root_box, *input_box, *button_box;
    GtkWidget *e_entry, *btn_blacklist, *btn_whitelist;
    GtkEntryBuffer* e_buffer;

    root_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_hexpand(state.root_box, TRUE);
    gtk_widget_add_css_class(window, "root");
    gtk_window_set_child(GTK_WINDOW(window), root_box);

    input_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_add_css_class(input_box, "popup-input-box");

    button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_add_css_class(button_box, "popup-input-box");
    gtk_widget_set_halign(button_box, GTK_ALIGN_END);

    e_buffer = gtk_entry_buffer_new(NULL, -1);
    e_entry = gtk_entry_new_with_buffer(e_buffer);
    gtk_widget_add_css_class(e_entry, "input-widget");
    gtk_widget_set_hexpand(e_entry, TRUE);

    btn_blacklist = gtk_button_new_with_label("blacklist");
    btn_whitelist = gtk_button_new_with_label("whitelist");
    g_signal_connect(GTK_BUTTON(btn_blacklist), "clicked", G_CALLBACK(query_insert_ips), e_entry);
    g_signal_connect(GTK_BUTTON(btn_whitelist), "clicked", G_CALLBACK(query_insert_ips), e_entry);

    box_append(root_box, input_box);
    box_append(root_box, button_box);

    box_append(input_box, e_entry);

    box_append(button_box, btn_blacklist);
    box_append(button_box, btn_whitelist);

    gtk_window_present(GTK_WINDOW(window));
}

int compar_rules_by_pkts(const void *a, const void *b){
    return ((Rule*)b)->pkts - ((Rule*)a)->pkts;
}

void on_reorder_rules_clicked(GtkButton* self, void* data){
    Rules _rules = {0};
    da_dump(_rules, (state.rules));

    qsort(_rules.items, _rules.count, sizeof(Rule), compar_rules_by_pkts);
    ipt_reorder(&_rules);
    ui_load_rules();

    da_free(_rules);
    return;
}

void populate_bottom_panel(){
    // Buttons
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_add_css_class(panel, "bottom-panel");

    GtkWidget *w_add_rule = gtk_button_new_with_label("Add Rule +");
    GtkWidget *w_refresh = gtk_button_new_with_label("Refresh 🗘");
    GtkWidget *w_bulk_ip = gtk_button_new_with_label("Blacklist/Whitelist IPs");
    GtkWidget *w_reorder_rules = gtk_button_new_with_label("Reorder Rules");
    
    g_signal_connect(GTK_BUTTON(w_refresh), "clicked", G_CALLBACK(ui_load_rules), NULL);
    g_signal_connect(GTK_BUTTON(w_add_rule), "clicked", G_CALLBACK(on_add_rule_clicked), NULL);
    g_signal_connect(GTK_BUTTON(w_bulk_ip), "clicked", G_CALLBACK(bulk_insert_ip), NULL);
    g_signal_connect(GTK_BUTTON(w_reorder_rules), "clicked", G_CALLBACK(on_reorder_rules_clicked), NULL);

    box_append(panel, w_add_rule);
    box_append(panel, w_refresh);
    box_append(panel, w_bulk_ip);
    box_append(panel, w_reorder_rules);

    root_append(state, panel);
}

GtkWidget* make_rules_info_header(){
    GtkWidget *w_num, *w_pkts, *w_prot, *w_target,
              *w_src, *w_dst, *w_spt, *w_dpt, *w_actions;
    GtkWidget* box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    w_num = gtk_label_new("num");

    w_pkts = gtk_label_new("pkts");
    w_prot = gtk_label_new("prot");
    w_target = gtk_label_new("target");
    w_src = gtk_label_new("src");
    w_dst = gtk_label_new("dst");
    w_spt = gtk_label_new("spt");
    w_dpt = gtk_label_new("dpt");
    w_actions = gtk_label_new("actions");

    // gtk_widget_set_hexpand(w_num, TRUE);
    gtk_widget_set_hexpand(w_pkts, TRUE);
    gtk_widget_set_hexpand(w_prot, TRUE);
    gtk_widget_set_hexpand(w_target, TRUE);
    gtk_widget_set_hexpand(w_src, TRUE);
    gtk_widget_set_hexpand(w_dst, TRUE);
    gtk_widget_set_hexpand(w_spt, TRUE);
    gtk_widget_set_hexpand(w_dpt, TRUE);

    gtk_size_group_add_widget(sg_num, w_num);
    gtk_size_group_add_widget(sg_pkts, w_pkts);
    gtk_size_group_add_widget(sg_prot, w_prot);
    gtk_size_group_add_widget(sg_target, w_target);
    gtk_size_group_add_widget(sg_src, w_src);
    gtk_size_group_add_widget(sg_dst, w_dst);
    gtk_size_group_add_widget(sg_spt, w_spt);
    gtk_size_group_add_widget(sg_dpt, w_dpt);
    gtk_size_group_add_widget(sg_actions, w_actions);

    box_append(box, w_num);
    box_append(box, w_pkts);
    box_append(box, w_prot);
    box_append(box, w_target);
    box_append(box, w_src);
    box_append(box, w_dst);
    box_append(box, w_spt);
    box_append(box, w_dpt);
    box_append(box, w_actions);

    return box;
}

GtkWidget* make_rule_box(const Rule rule){
    GtkWidget *w_num, *w_pkts, *w_prot, *w_target, *w_src, *w_dst, *w_spt, *w_dpt, *w_separator;
    GtkWidget *actions_box, *w_delete, *w_edit;
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

    snprintf(str_buffer, sizeof(str_buffer), "%d", rule.sport);
    w_spt = gtk_label_new(rule.sport >= 0 ? str_buffer : NULL);
    snprintf(str_buffer, sizeof(str_buffer), "%d",rule.dport);
    w_dpt = gtk_label_new(rule.dport >= 0 ? str_buffer : NULL);

    // Actions 
    w_delete = gtk_button_new_from_icon_name("delete");
    w_edit = gtk_button_new_from_icon_name("edit");
    actions_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);

    w_separator = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);

    // gtk_widget_set_hexpand(w_num, TRUE);
    gtk_widget_set_hexpand(w_pkts, TRUE);
    gtk_widget_set_hexpand(w_prot, TRUE);
    gtk_widget_set_hexpand(w_target, TRUE);
    gtk_widget_set_hexpand(w_src, TRUE);
    gtk_widget_set_hexpand(w_dst, TRUE);
    gtk_widget_set_hexpand(w_spt, TRUE);
    gtk_widget_set_hexpand(w_dpt, TRUE);

    gtk_size_group_add_widget(sg_num, w_num);
    gtk_size_group_add_widget(sg_pkts, w_pkts);
    gtk_size_group_add_widget(sg_prot, w_prot);
    gtk_size_group_add_widget(sg_target, w_target);
    gtk_size_group_add_widget(sg_src, w_src);
    gtk_size_group_add_widget(sg_dst, w_dst);
    gtk_size_group_add_widget(sg_spt, w_spt);
    gtk_size_group_add_widget(sg_dpt, w_dpt);
    gtk_size_group_add_widget(sg_actions, actions_box);

    gtk_widget_add_css_class(w_edit, "action-widgets");
    gtk_widget_add_css_class(w_delete, "action-widgets");

    g_signal_connect(GTK_BUTTON(w_delete), "clicked", G_CALLBACK(on_delete_rule), GINT_TO_POINTER(rule.num));
    g_signal_connect(GTK_BUTTON(w_edit), "clicked", G_CALLBACK(on_edit_rule), GINT_TO_POINTER(rule.num));

    box_append(box, w_num);
    box_append(box, w_pkts);
    box_append(box, w_prot);
    box_append(box, w_target);
    box_append(box, w_src);
    box_append(box, w_dst);
    box_append(box, w_spt);
    box_append(box, w_dpt);
    box_append(box, actions_box);
    box_append(actions_box, w_edit);
    box_append(actions_box, w_delete);

    box_append(state.rules_box, w_separator);

    return box;
}

void ui_load_rules(){
    box_clear_children(state.rules_box);
    box_append(state.rules_box, make_rules_info_header());

    state.rules.count = 0;

    ipt_save_rule_listing_to_file("tables.tmp");
    if (!parse_rules_from_file("tables.tmp", &state.rules)){
        for (size_t i = 0;  i < state.rules.count; i++) {
            box_append(state.rules_box, make_rule_box(state.rules.items[i]));
        }
    }
}

void ui_activate(GtkApplication* app){
    state.window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(state.window), "iptables");
    gtk_window_set_default_size(GTK_WINDOW(state.window), WINDOW_WIDTH, WINDOW_HEIGHT);

    // Add root box
    state.root_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_hexpand(state.root_box, TRUE);
    gtk_widget_add_css_class(state.window, "root");
    gtk_window_set_child(GTK_WINDOW(state.window), state.root_box);

    populate_top_panel();
    populate_rule_listing_box();
    populate_bottom_panel();

    load_css();

    gtk_window_present(GTK_WINDOW(state.window));
}
