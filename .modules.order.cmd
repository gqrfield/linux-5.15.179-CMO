cmd_cmo/modules.order := {   cat cmo/nonblocking/modules.order;   cat cmo/perpage/modules.order; :; } | awk '!x[$$0]++' - > cmo/modules.order
