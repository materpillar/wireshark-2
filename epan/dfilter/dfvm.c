/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include "dfvm.h"

#include <ftypes/ftypes.h>
#include <wsutil/ws_assert.h>

static void
debug_register(GSList *reg, guint32 num);

const char *
dfvm_opcode_tostr(dfvm_opcode_t code)
{
	switch (code) {
		case DFVM_IF_TRUE_GOTO:		return "IF_TRUE_GOTO";
		case DFVM_IF_FALSE_GOTO:	return "IF_FALSE_GOTO";
		case DFVM_CHECK_EXISTS:		return "CHECK_EXISTS";
		case DFVM_CHECK_EXISTS_R:	return "CHECK_EXISTS_R";
		case DFVM_NOT:			return "NOT";
		case DFVM_RETURN:		return "RETURN";
		case DFVM_READ_TREE:		return "READ_TREE";
		case DFVM_READ_TREE_R:		return "READ_TREE_R";
		case DFVM_READ_REFERENCE:	return "READ_REFERENCE";
		case DFVM_READ_REFERENCE_R:	return "READ_REFERENCE_R";
		case DFVM_PUT_FVALUE:		return "PUT_FVALUE";
		case DFVM_ALL_EQ:		return "ALL_EQ";
		case DFVM_ANY_EQ:		return "ANY_EQ";
		case DFVM_ALL_NE:		return "ALL_NE";
		case DFVM_ANY_NE:		return "ANY_NE";
		case DFVM_ALL_GT:		return "ALL_GT";
		case DFVM_ANY_GT:		return "ANY_GT";
		case DFVM_ALL_GE:		return "ALL_GE";
		case DFVM_ANY_GE:		return "ANY_GE";
		case DFVM_ALL_LT:		return "ALL_LT";
		case DFVM_ANY_LT:		return "ANY_LT";
		case DFVM_ALL_LE:		return "ALL_LE";
		case DFVM_ANY_LE:		return "ANY_LE";
		case DFVM_ALL_CONTAINS:		return "ALL_CONTAINS";
		case DFVM_ANY_CONTAINS:		return "ANY_CONTAINS";
		case DFVM_ALL_MATCHES:		return "ALL_MATCHES";
		case DFVM_ANY_MATCHES:		return "ANY_MATCHES";
		case DFVM_ALL_IN_RANGE:		return "ALL_IN_RANGE";
		case DFVM_ANY_IN_RANGE:		return "ANY_IN_RANGE";
		case DFVM_SLICE:		return "SLICE";
		case DFVM_LENGTH:		return "LENGTH";
		case DFVM_BITWISE_AND:		return "BITWISE_AND";
		case DFVM_UNARY_MINUS:		return "UNARY_MINUS";
		case DFVM_ADD:			return "ADD";
		case DFVM_SUBTRACT:		return "SUBTRACT";
		case DFVM_MULTIPLY:		return "MULTIPLY";
		case DFVM_DIVIDE:		return "DIVIDE";
		case DFVM_MODULO:		return "MODULO";
		case DFVM_CALL_FUNCTION:	return "CALL_FUNCTION";
		case DFVM_STACK_PUSH:		return "STACK_PUSH";
		case DFVM_STACK_POP:		return "STACK_POP";
		case DFVM_NOT_ALL_ZERO:		return "NOT_ALL_ZERO";
	}
	return "(fix-opcode-string)";
}

dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op)
{
	dfvm_insn_t	*insn;

	insn = g_new(dfvm_insn_t, 1);
	insn->op = op;
	insn->arg1 = NULL;
	insn->arg2 = NULL;
	insn->arg3 = NULL;
	return insn;
}

static void
dfvm_value_free(dfvm_value_t *v)
{
	switch (v->type) {
		case FVALUE:
			fvalue_free(v->value.fvalue);
			break;
		case DRANGE:
			drange_free(v->value.drange);
			break;
		case PCRE:
			ws_regex_free(v->value.pcre);
			break;
		case EMPTY:
		case HFINFO:
		case RAW_HFINFO:
		case INSN_NUMBER:
		case REGISTER:
		case INTEGER:
		case FUNCTION_DEF:
			break;
	}
	g_free(v);
}

dfvm_value_t*
dfvm_value_ref(dfvm_value_t *v)
{
	if (v == NULL)
		return NULL;
	v->ref_count++;
	return v;
}

void
dfvm_value_unref(dfvm_value_t *v)
{
	ws_assert(v);
	v->ref_count--;
	if (v->ref_count > 0)
		return;
	dfvm_value_free(v);
}

void
dfvm_insn_free(dfvm_insn_t *insn)
{
	if (insn->arg1) {
		dfvm_value_unref(insn->arg1);
	}
	if (insn->arg2) {
		dfvm_value_unref(insn->arg2);
	}
	if (insn->arg3) {
		dfvm_value_unref(insn->arg3);
	}
	g_free(insn);
}


dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type)
{
	dfvm_value_t	*v;

	v = g_new(dfvm_value_t, 1);
	v->type = type;
	v->ref_count = 0;
	return v;
}

dfvm_value_t*
dfvm_value_new_fvalue(fvalue_t *fv)
{
	dfvm_value_t *v = dfvm_value_new(FVALUE);
	v->value.fvalue = fv;
	return v;
}

dfvm_value_t*
dfvm_value_new_hfinfo(header_field_info *hfinfo, gboolean raw)
{
	dfvm_value_t *v;

	if (raw)
		v = dfvm_value_new(RAW_HFINFO);
	else
		v = dfvm_value_new(HFINFO);
	v->value.hfinfo = hfinfo;
	return v;
}

dfvm_value_t*
dfvm_value_new_register(int reg)
{
	dfvm_value_t *v = dfvm_value_new(REGISTER);
	v->value.numeric = reg;
	return v;
}

dfvm_value_t*
dfvm_value_new_drange(drange_t *dr)
{
	dfvm_value_t *v = dfvm_value_new(DRANGE);
	v->value.drange = dr;
	return v;
}

dfvm_value_t*
dfvm_value_new_funcdef(df_func_def_t *funcdef)
{
	dfvm_value_t *v = dfvm_value_new(FUNCTION_DEF);
	v->value.funcdef = funcdef;
	return v;
}

dfvm_value_t*
dfvm_value_new_pcre(ws_regex_t *re)
{
	dfvm_value_t *v = dfvm_value_new(PCRE);
	v->value.pcre = re;
	return v;
}

dfvm_value_t*
dfvm_value_new_guint(guint num)
{
	dfvm_value_t *v = dfvm_value_new(INTEGER);
	v->value.numeric = num;
	return v;
}

static char *
dfvm_value_tostr(dfvm_value_t *v)
{
	char *s;

	if (!v)
		return NULL;

	switch (v->type) {
		case HFINFO:
			s = ws_strdup(v->value.hfinfo->abbrev);
			break;
		case RAW_HFINFO:
			s = ws_strdup_printf("@%s", v->value.hfinfo->abbrev);
			break;
		case FVALUE:
			s = fvalue_to_debug_repr(NULL, v->value.fvalue);
			break;
		case DRANGE:
			s = drange_tostr(v->value.drange);
			break;
		case PCRE:
			s = ws_strdup(ws_regex_pattern(v->value.pcre));
			break;
		case REGISTER:
			s = ws_strdup_printf("R%"G_GUINT32_FORMAT, v->value.numeric);
			break;
		case FUNCTION_DEF:
			s = ws_strdup(v->value.funcdef->name);
			break;
		case INTEGER:
			s = ws_strdup_printf("%"G_GUINT32_FORMAT, v->value.numeric);
			break;
		default:
			s = ws_strdup("FIXME");
	}
	return s;
}

static char *
value_type_tostr(dfvm_value_t *v, gboolean show_ftype)
{
	const char *s;

	if (!v || !show_ftype)
		return ws_strdup("");

	switch (v->type) {
		case HFINFO:
			s = ftype_name(v->value.hfinfo->type);
			break;
		case RAW_HFINFO:
			s = "FT_BYTES";
			break;
		case FVALUE:
			s = fvalue_type_name(v->value.fvalue);
			break;
		default:
			return ws_strdup("");
			break;
	}
	return ws_strdup_printf(" <%s>", s);
}

static GSList *
dump_str_stack_push(GSList *stack, const char *str)
{
	return g_slist_prepend(stack, g_strdup(str));
}

static GSList *
dump_str_stack_pop(GSList *stack, guint32 count)
{
	while (stack && count-- > 0) {
		g_free(stack->data);
		stack = g_slist_delete_link(stack, stack);
	}
	return stack;
}

static void
append_call_function(wmem_strbuf_t *buf, const char *func, uint32_t nargs,
					GSList *stack_print)
{
	uint32_t idx;
	GString	*gs;
	GSList *l;
	const char *sep = "";

	wmem_strbuf_append_printf(buf, "%s(", func);
	if (nargs > 0) {
		gs = g_string_new(NULL);
		for (l = stack_print, idx = 0; l != NULL && idx < nargs; idx++, l = l->next) {
			g_string_prepend(gs, sep);
			g_string_prepend(gs, l->data);
			sep = ", ";
		}
		wmem_strbuf_append(buf, gs->str);
		g_string_free(gs, TRUE);
	}
	wmem_strbuf_append(buf, ")");
}

static void
indent(wmem_strbuf_t *buf, size_t offset, size_t start)
{
	size_t pos = buf->len - start;
	if (pos >= offset)
		return;
	wmem_strbuf_append_c_count(buf, ' ', offset - pos);
}
#define indent1(buf, start) indent(buf, 24, start)
#define indent2(buf, start) indent(buf, 16, start)

static void
append_to_register(wmem_strbuf_t *buf, const char *reg)
{
	wmem_strbuf_append_printf(buf, " -> %s", reg);
}

static void
append_op_args(wmem_strbuf_t *buf, dfvm_insn_t *insn, GSList **stack_print,
							uint16_t flags)
{
	dfvm_value_t	*arg1, *arg2, *arg3;
	char 		*arg1_str, *arg2_str, *arg3_str;
	char 		*arg1_str_type, *arg2_str_type, *arg3_str_type;
	size_t		col_start;

	arg1 = insn->arg1;
	arg2 = insn->arg2;
	arg3 = insn->arg3;
	arg1_str = dfvm_value_tostr(arg1);
	arg2_str = dfvm_value_tostr(arg2);
	arg3_str = dfvm_value_tostr(arg3);
	arg1_str_type = value_type_tostr(arg1, flags & DF_DUMP_SHOW_FTYPE);
	arg2_str_type = value_type_tostr(arg2, flags & DF_DUMP_SHOW_FTYPE);
	arg3_str_type = value_type_tostr(arg3, flags & DF_DUMP_SHOW_FTYPE);

	col_start = buf->len;

	switch (insn->op) {
		case DFVM_CHECK_EXISTS:
			wmem_strbuf_append_printf(buf, "%s%s",
						arg1_str, arg1_str_type);
			break;

		case DFVM_CHECK_EXISTS_R:
			wmem_strbuf_append_printf(buf, "%s#[%s]%s",
						arg1_str, arg2_str, arg1_str_type);
			break;

		case DFVM_READ_TREE:
			wmem_strbuf_append_printf(buf, "%s%s",
						arg1_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_READ_TREE_R:
			wmem_strbuf_append_printf(buf, "%s#[%s]%s",
						arg1_str, arg3_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_READ_REFERENCE:
			wmem_strbuf_append_printf(buf, "${%s}%s",
						arg1_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_READ_REFERENCE_R:
			wmem_strbuf_append_printf(buf, "${%s#[%s]}%s",
						arg1_str, arg3_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_PUT_FVALUE:
			wmem_strbuf_append_printf(buf, "%s%s",
						arg1_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_CALL_FUNCTION:
			append_call_function(buf, arg1_str, arg3->value.numeric, *stack_print);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_STACK_PUSH:
			wmem_strbuf_append_printf(buf, "%s", arg1_str);
			*stack_print = dump_str_stack_push(*stack_print, arg1_str);
			break;

		case DFVM_STACK_POP:
			wmem_strbuf_append_printf(buf, "%s", arg1_str);
			*stack_print = dump_str_stack_pop(*stack_print, arg1->value.numeric);
			break;

		case DFVM_SLICE:
			wmem_strbuf_append_printf(buf, "%s[%s]%s",
						arg1_str, arg3_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_LENGTH:
			wmem_strbuf_append_printf(buf, "%s%s",
						arg1_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_ALL_EQ:
			wmem_strbuf_append_printf(buf, "%s%s === %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ANY_EQ:
			wmem_strbuf_append_printf(buf, "%s%s == %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_NE:
			wmem_strbuf_append_printf(buf, "%s%s != %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ANY_NE:
			wmem_strbuf_append_printf(buf, "%s%s !== %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_GT:
		case DFVM_ANY_GT:
			wmem_strbuf_append_printf(buf, "%s%s > %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_GE:
		case DFVM_ANY_GE:
			wmem_strbuf_append_printf(buf, "%s%s >= %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_LT:
		case DFVM_ANY_LT:
			wmem_strbuf_append_printf(buf, "%s%s < %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_LE:
		case DFVM_ANY_LE:
			wmem_strbuf_append_printf(buf, "%s%s <= %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_NOT_ALL_ZERO:
			wmem_strbuf_append_printf(buf, "%s%s",
						arg1_str, arg1_str_type);
			break;

		case DFVM_ALL_CONTAINS:
		case DFVM_ANY_CONTAINS:
			wmem_strbuf_append_printf(buf, "%s%s contains %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_MATCHES:
		case DFVM_ANY_MATCHES:
			wmem_strbuf_append_printf(buf, "%s%s matches %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			break;

		case DFVM_ALL_IN_RANGE:
		case DFVM_ANY_IN_RANGE:
			wmem_strbuf_append_printf(buf, "%s%s in { %s%s .. %s%s }",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type, arg3_str, arg3_str_type);
			break;

		case DFVM_BITWISE_AND:
			wmem_strbuf_append_printf(buf, "%s%s & %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg3_str);
			break;

		case DFVM_UNARY_MINUS:
			wmem_strbuf_append_printf(buf, "-%s%s",
						arg1_str, arg1_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg2_str);
			break;

		case DFVM_ADD:
			wmem_strbuf_append_printf(buf, "%s%s + %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg3_str);
			break;

		case DFVM_SUBTRACT:
			wmem_strbuf_append_printf(buf, "%s%s - %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg3_str);
			break;

		case DFVM_MULTIPLY:
			wmem_strbuf_append_printf(buf, "%s%s * %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg3_str);
			break;

		case DFVM_DIVIDE:
			wmem_strbuf_append_printf(buf, "%s%s / %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg3_str);
			break;

		case DFVM_MODULO:
			wmem_strbuf_append_printf(buf, "%s%s %% %s%s",
						arg1_str, arg1_str_type, arg2_str, arg2_str_type);
			indent2(buf, col_start);
			append_to_register(buf, arg3_str);
			break;

		case DFVM_IF_TRUE_GOTO:
		case DFVM_IF_FALSE_GOTO:
			wmem_strbuf_append_printf(buf, "%u", arg1->value.numeric);
			break;

		case DFVM_NOT:
		case DFVM_RETURN:
			ws_assert_not_reached();
	}

	g_free(arg1_str);
	g_free(arg2_str);
	g_free(arg3_str);
	g_free(arg1_str_type);
	g_free(arg2_str_type);
	g_free(arg3_str_type);
}

static void
append_references(wmem_strbuf_t *buf, GHashTable *references, gboolean raw)
{
	GHashTableIter	ref_iter;
	gpointer	key, value;
	char		*str;
	guint		i;

	g_hash_table_iter_init(&ref_iter, references);
	while (g_hash_table_iter_next(&ref_iter, &key, &value)) {
		const char *abbrev = ((header_field_info *)key)->abbrev;
		GPtrArray *refs_array = value;
		df_reference_t *ref;

		if (raw)
			wmem_strbuf_append_printf(buf, " ${@%s} = {", abbrev);
		else
			wmem_strbuf_append_printf(buf, " ${%s} = {", abbrev);
		for (i = 0; i < refs_array->len; i++) {
			if (i != 0) {
				wmem_strbuf_append(buf, ", ");
			}
			ref = refs_array->pdata[i];
			str = fvalue_to_debug_repr(NULL, ref->value);
			wmem_strbuf_append_printf(buf, "%s <%s>", str, fvalue_type_name(ref->value));
			g_free(str);
		}
		wmem_strbuf_append(buf, "}\n");
	}
}

char *
dfvm_dump_str(wmem_allocator_t *alloc, dfilter_t *df, uint16_t flags)
{
	int		id, length;
	dfvm_insn_t	*insn;
	wmem_strbuf_t	*buf;
	GSList		*stack_print = NULL;
	size_t		col_start;

	buf = wmem_strbuf_new(alloc, NULL);

	if (flags & DF_DUMP_REFERENCES) {
		if (g_hash_table_size(df->references) > 0) {
			wmem_strbuf_append(buf, "References:\n");
			append_references(buf, df->references, FALSE);
		}
		else {
			wmem_strbuf_append(buf, "References: (none)\n");
		}
		wmem_strbuf_append_c(buf, '\n');
	}

	if (flags & DF_DUMP_REFERENCES) {
		if (g_hash_table_size(df->raw_references) > 0) {
			wmem_strbuf_append(buf, "Raw references:\n");
			append_references(buf, df->raw_references, TRUE);
		}
		else {
			wmem_strbuf_append(buf, "Raw references: (none)\n");
		}
		wmem_strbuf_append_c(buf, '\n');
	}

	wmem_strbuf_append(buf, "Instructions:");

	length = df->insns->len;
	for (id = 0; id < length; id++) {
		insn = g_ptr_array_index(df->insns, id);
		col_start = buf->len;
		wmem_strbuf_append_printf(buf, "\n %04d %s", id, dfvm_opcode_tostr(insn->op));

		switch (insn->op) {
			case DFVM_NOT:
			case DFVM_RETURN:
				/* Nothing here */
				break;
			default:
				indent1(buf, col_start);
				append_op_args(buf, insn, &stack_print, flags);
				break;
		}
	}

	return wmem_strbuf_finalize(buf);
}

void
dfvm_dump(FILE *f, dfilter_t *df, uint16_t flags)
{
	char *str = dfvm_dump_str(NULL, df, flags);
	fputs(str, f);
	fputc('\n', f);
	wmem_free(NULL, str);
}

static int
compare_finfo_layer(gconstpointer _a, gconstpointer _b)
{
	const field_info *a = *(const field_info **)_a;
	const field_info *b = *(const field_info **)_b;
	return a->proto_layer_num - b->proto_layer_num;
}

static gboolean
drange_contains_layer(drange_t *dr, int num, int length)
{
	drange_node *rn;
	GSList *list = dr->range_list;
	int lower, upper;

	while (list) {
		rn = list->data;
		lower = rn->start_offset;
		if (lower < 0) {
			lower += length + 1;
		}
		if (rn->ending == DRANGE_NODE_END_T_LENGTH) {
			upper = lower + rn->length - 1;
		}
		else if (rn->ending == DRANGE_NODE_END_T_OFFSET) {
			upper = rn->end_offset;
		}
		else if (rn->ending == DRANGE_NODE_END_T_TO_THE_END) {
			upper = INT_MAX;
		}
		else {
			ws_assert_not_reached();
		}

		if (num >= lower && num <= upper) {  /* inclusive */
			return TRUE;
		}

		list = g_slist_next(list);
	}
	return FALSE;
}

fvalue_t *
dfvm_get_raw_fvalue(const field_info *fi)
{
	GByteArray *bytes;
	fvalue_t *fv;
	int length, tvb_length;

	/*
	 * XXX - a field can have a length that runs past
	 * the end of the tvbuff.  Ideally, that should
	 * be fixed when adding an item to the protocol
	 * tree, but checking the length when doing
	 * that could be expensive.  Until we fix that,
	 * we'll do the check here.
	 */
	tvb_length = tvb_captured_length_remaining(fi->ds_tvb, fi->start);
	if (tvb_length < 0) {
		return NULL;
	}
	length = fi->length;
	if (length > tvb_length)
		length = tvb_length;

	bytes = g_byte_array_new();
	g_byte_array_append(bytes, tvb_get_ptr(fi->ds_tvb, fi->start, length), length);

	fv = fvalue_new(FT_BYTES);
	fvalue_set_byte_array(fv, bytes);
	return fv;
}

static size_t
filter_finfo_fvalues(df_cell_t *rp, GPtrArray *finfos, drange_t *range, gboolean raw)
{
	int length; /* maximum proto layer number. The numbers are sequential. */
	field_info *last_finfo, *finfo;
	fvalue_t *fv;
	int cookie = -1;
	gboolean cookie_matches = false;
	int layer;
	size_t count = 0;

	g_ptr_array_sort(finfos, compare_finfo_layer);
	last_finfo = finfos->pdata[finfos->len - 1];
	length = last_finfo->proto_layer_num;

	for (guint i = 0; i < finfos->len; i++) {
		finfo = finfos->pdata[i];
		layer = finfo->proto_layer_num;
		if (cookie == layer) {
			if (cookie_matches) {
				if (rp != NULL) {
					if (raw)
						fv = dfvm_get_raw_fvalue(finfo);
					else
						fv = finfo->value;
					df_cell_append(rp, fv);
				}
				count++;
			}
		}
		else {
			cookie = layer;
			cookie_matches = drange_contains_layer(range, layer, length);
			if (cookie_matches) {
				if (rp != NULL) {
					if (raw)
						fv = dfvm_get_raw_fvalue(finfo);
					else
						fv = finfo->value;
					df_cell_append(rp, fv);
				}
				count++;
			}
		}
	}
	return count;
}

static gboolean
read_tree_finfos(df_cell_t *rp, proto_tree *tree,
			header_field_info *hfinfo, drange_t *range, gboolean raw)
{
	GPtrArray	*finfos;
	field_info	*finfo;
	fvalue_t	*fv;

	/* The caller should NOT free the GPtrArray. */
	finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);
	if (finfos == NULL || g_ptr_array_len(finfos) == 0) {
		return FALSE;
	}
	if (range) {
		return filter_finfo_fvalues(rp, finfos, range, raw) > 0;
	}

	for (guint i = 0; i < finfos->len; i++) {
		finfo = g_ptr_array_index(finfos, i);
		if (raw)
			fv = dfvm_get_raw_fvalue(finfo);
		else
			fv = finfo->value;
		df_cell_append(rp, fv);
	}
	return TRUE;
}

/* Reads a field from the proto_tree and loads the fvalues into a register,
 * if that field has not already been read. */
static gboolean
read_tree(dfilter_t *df, proto_tree *tree,
				dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3)
{
	drange_t	*range = NULL;
	gboolean	raw;
	df_cell_t	*rp;

	header_field_info *hfinfo = arg1->value.hfinfo;
	raw = arg1->type == RAW_HFINFO;

	int reg = arg2->value.numeric;

	if (arg3) {
		range = arg3->value.drange;
	}

	rp = &df->registers[reg];

	/* Already loaded in this run of the dfilter? */
	if (!df_cell_is_null(rp)) {
		return !df_cell_is_empty(rp);
	}

	if (raw) {
		df_cell_init(rp, TRUE);
	}
	else {
		// These values are referenced only, do not try to free it later.
		df_cell_init(rp, FALSE);
	}

	while (hfinfo) {
		read_tree_finfos(rp, tree, hfinfo, range, raw);
		hfinfo = hfinfo->same_name_next;
	}

	return !df_cell_is_empty(rp);
}

static void
filter_refs_fvalues(df_cell_t *rp, GPtrArray *refs_array, drange_t *range)
{
	int length; /* maximum proto layer number. The numbers are sequential. */
	df_reference_t *last_ref = NULL;
	int cookie = -1;
	gboolean cookie_matches = false;

	if (!refs_array || refs_array->len == 0) {
		return;
	}

	/* refs array is sorted. */
	last_ref = refs_array->pdata[refs_array->len - 1];
	length = last_ref->proto_layer_num;

	for (guint i = 0; i < refs_array->len; i++) {
		df_reference_t *ref = refs_array->pdata[i];
		int layer = ref->proto_layer_num;

		if (range == NULL) {
			df_cell_append(rp, ref->value);
			continue;
		}

		if (cookie == layer) {
			if (cookie_matches) {
				df_cell_append(rp, ref->value);
			}
		}
		else {
			cookie = layer;
			cookie_matches = drange_contains_layer(range, layer, length);
			if (cookie_matches) {
				df_cell_append(rp, ref->value);
			}
		}
	}
}

static gboolean
read_reference(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
				dfvm_value_t *arg3)
{
	df_cell_t *rp;
	GPtrArray	*refs;
	drange_t	*range = NULL;
	gboolean	raw;

	header_field_info *hfinfo = arg1->value.hfinfo;
	raw = arg1->type == RAW_HFINFO;

	int reg = arg2->value.numeric;

	if (arg3) {
		range = arg3->value.drange;
	}

	rp = &df->registers[reg];

	/* Already loaded in this run of the dfilter? */
	if (!df_cell_is_null(rp)) {
		return !df_cell_is_empty(rp);
	}

	refs = g_hash_table_lookup(raw ? df->raw_references : df->references, hfinfo);
	if (refs == NULL || refs->len == 0) {
		return FALSE;
	}

	// These values are referenced only, do not try to free it later.
	df_cell_init(rp, FALSE);
	filter_refs_fvalues(rp, refs, range);
	return TRUE;
}

enum match_how {
	MATCH_ANY,
	MATCH_ALL
};

typedef ft_bool_t (*DFVMCompareFunc)(const fvalue_t*, const fvalue_t*);
typedef ft_bool_t (*DFVMTestFunc)(const fvalue_t*);

static gboolean
cmp_test_internal(enum match_how how, DFVMCompareFunc match_func,
			const fvalue_t **fv_ptr1, size_t fv_count1,
			const fvalue_t **fv_ptr2, size_t fv_count2)
{
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	ft_bool_t have_match;

	for (size_t idx1 = 0; idx1 < fv_count1; idx1++) {
		for (size_t idx2 = 0; idx2 < fv_count2; idx2++) {
			have_match = match_func(fv_ptr1[idx1], fv_ptr2[idx2]);
			if (want_all && have_match == FT_FALSE) {
				return FALSE;
			}
			else if (want_any && have_match == FT_TRUE) {
				return TRUE;
			}
		}
	}
	/* want_all || !want_any */
	return want_all;
}

static gboolean
cmp_test_unary(enum match_how how, DFVMTestFunc test_func,
			const fvalue_t **fv_ptr, size_t fv_count)
{
	gboolean want_all = (how == MATCH_ALL);
	gboolean want_any = (how == MATCH_ANY);
	ft_bool_t have_match;

	for (size_t idx = 0; idx < fv_count; idx++) {
		have_match = test_func(fv_ptr[idx]);
		if (want_all && have_match == FT_FALSE) {
			return FALSE;
		}
		else if (want_any && have_match == FT_TRUE) {
			return TRUE;
		}
	}
	/* want_all || !want_any */
	return want_all;
}

static gboolean
all_test_unary(dfilter_t *df, DFVMTestFunc func, dfvm_value_t *arg1)
{
	ws_assert(arg1->type == REGISTER);
	df_cell_t *rp = &df->registers[arg1->value.numeric];
	return cmp_test_unary(MATCH_ALL, func,
			(const fvalue_t **)df_cell_array(rp), df_cell_size(rp));
}

static gboolean
cmp_test(dfilter_t *df, DFVMCompareFunc cmp,
			dfvm_value_t *arg1, dfvm_value_t *arg2,
			enum match_how how)
{
	df_cell_t *rp1 = &df->registers[arg1->value.numeric];
	const fvalue_t **fv_ptr1;
	size_t fv_count1;

	if (arg1->type == REGISTER) {
		fv_ptr1 = (const fvalue_t **)df_cell_array(rp1);
		fv_count1 = df_cell_size(rp1);
	}
	else if (arg1->type == FVALUE) {
		fv_ptr1 = (const fvalue_t **)&arg1->value.fvalue;
		fv_count1 = 1;
	}
	else {
		ws_assert_not_reached();
	}

	df_cell_t *rp2 = &df->registers[arg2->value.numeric];
	const fvalue_t **fv_ptr2;
	size_t fv_count2;

	if (arg2->type == REGISTER) {
		fv_ptr2 = (const fvalue_t **)df_cell_array(rp2);
		fv_count2 = df_cell_size(rp2);
	}
	else if (arg2->type == FVALUE) {
		fv_ptr2 = (const fvalue_t **)&arg2->value.fvalue;
		fv_count2 = 1;
	}
	else {
		ws_assert_not_reached();
	}

	return cmp_test_internal(how, cmp,
			fv_ptr1, fv_count1, fv_ptr2, fv_count2);
}

/* cmp(A) <=> cmp(a1) OR cmp(a2) OR cmp(a3) OR ... */
static inline gboolean
any_test(dfilter_t *df, DFVMCompareFunc cmp,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	return cmp_test(df, cmp, arg1, arg2, MATCH_ANY);
}

/* cmp(A) <=> cmp(a1) AND cmp(a2) AND cmp(a3) AND ... */
static gboolean
all_test(dfilter_t *df, DFVMCompareFunc cmp,
				dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	return cmp_test(df, cmp, arg1, arg2, MATCH_ALL);
}

static gboolean
any_matches(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	df_cell_t *rp = &df->registers[arg1->value.numeric];
	ws_regex_t *re = arg2->value.pcre;

	const fvalue_t **fv_ptr = (const fvalue_t **)df_cell_array(rp);

	for (size_t idx = 0; idx < df_cell_size(rp); idx++) {
		if (fvalue_matches(fv_ptr[idx], re) == FT_TRUE) {
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
all_matches(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	df_cell_t *rp = &df->registers[arg1->value.numeric];
	ws_regex_t *re = arg2->value.pcre;

	const fvalue_t **fv_ptr = (const fvalue_t **)df_cell_array(rp);

	for (size_t idx = 0; idx < df_cell_size(rp); idx++) {
		if (fvalue_matches(fv_ptr[idx], re) == FT_FALSE) {
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean
any_in_range_internal(df_cell_t *rp, const fvalue_t *low, const fvalue_t *high)
{
	const fvalue_t **fv_ptr = (const fvalue_t **)df_cell_array(rp);

	for (size_t idx = 0; idx < df_cell_size(rp); idx++) {
		if (fvalue_ge(fv_ptr[idx], low) == FT_TRUE &&
				fvalue_le(fv_ptr[idx], high) == FT_TRUE) {
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
all_in_range_internal(df_cell_t *rp, const fvalue_t *low, const fvalue_t *high)
{
	const fvalue_t **fv_ptr = (const fvalue_t **)df_cell_array(rp);

	for (size_t idx = 0; idx < df_cell_size(rp); idx++) {
		if (fvalue_ge(fv_ptr[idx], low) == FT_FALSE ||
				fvalue_le(fv_ptr[idx], high) == FT_FALSE) {
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean
match_in_range(dfilter_t *df, enum match_how how, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	df_cell_t *rp1 = &df->registers[arg1->value.numeric];
	df_cell_t *rp_low, *rp_high;
	const fvalue_t *low, *high;

	if (arg_low->type == REGISTER) {
		rp_low = &df->registers[arg_low->value.numeric];
		ws_assert(df_cell_size(rp_low) == 1);
		low = *(const fvalue_t **)df_cell_array(rp_low);
	}
	else if (arg_low->type == FVALUE) {
		low = arg_low->value.fvalue;
	}
	else {
		ws_assert_not_reached();
	}

	if (arg_high->type == REGISTER) {
		rp_high = &df->registers[arg_high->value.numeric];
		ws_assert(df_cell_size(rp_high) == 1);
		high = *(const fvalue_t **)df_cell_array(rp_high);
	}
	else if (arg_high->type == FVALUE) {
		high = arg_high->value.fvalue;
	}
	else {
		ws_assert_not_reached();
	}

	if (how == MATCH_ALL)
		return all_in_range_internal(rp1, low, high);
	else if (how == MATCH_ANY)
		return any_in_range_internal(rp1, low, high);
	else
		ws_assert_not_reached();
}

static gboolean
any_in_range(dfilter_t *df, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	return match_in_range(df, MATCH_ANY, arg1, arg_low, arg_high);
}

static gboolean
all_in_range(dfilter_t *df, dfvm_value_t *arg1,
				dfvm_value_t *arg_low, dfvm_value_t *arg_high)
{
	return match_in_range(df, MATCH_ALL, arg1, arg_low, arg_high);
}

/* Clear registers that were populated during evaluation.
 * If we created the values, then these will be freed as well. */
static void
free_register_overhead(dfilter_t* df)
{
	for (guint i = 0; i < df->num_registers; i++) {
		df_cell_clear(&df->registers[i]);
	}
}

/* Takes the list of fvalue_t's in a register, uses fvalue_slice()
 * to make a new list of fvalue_t's (which are byte-slices),
 * and puts the new list into a new register. */
static void
mk_slice(dfilter_t *df, dfvm_value_t *from_arg, dfvm_value_t *to_arg,
						dfvm_value_t *drange_arg)
{
	df_cell_t *from_rp, *to_rp;
	df_cell_iter_t from_iter;
	fvalue_t *old_fv;
	fvalue_t *new_fv;

	to_rp = &df->registers[to_arg->value.numeric];
	df_cell_init(to_rp, TRUE);
	from_rp = &df->registers[from_arg->value.numeric];
	drange_t *drange = drange_arg->value.drange;

	df_cell_iter_init(from_rp, &from_iter);
	while ((old_fv = df_cell_iter_next(&from_iter)) != NULL) {
		new_fv = fvalue_slice(old_fv, drange);
		/* Assert here because semcheck.c should have
		 * already caught the cases in which a slice
		 * cannot be made. */
		ws_assert(new_fv);
		df_cell_append(to_rp, new_fv);
	}
}

static void
mk_length(dfilter_t *df, dfvm_value_t *from_arg, dfvm_value_t *to_arg)
{
	df_cell_t *from_rp, *to_rp;
	df_cell_iter_t from_iter;
	fvalue_t *old_fv;
	fvalue_t *new_fv;

	to_rp = &df->registers[to_arg->value.numeric];
	df_cell_init(to_rp, TRUE);
	from_rp = &df->registers[from_arg->value.numeric];

	df_cell_iter_init(from_rp, &from_iter);
	while ((old_fv = df_cell_iter_next(&from_iter)) != NULL) {
		new_fv = fvalue_new(FT_UINT32);
		fvalue_set_uinteger(new_fv, (guint32)fvalue_length2(old_fv));
		df_cell_append(to_rp, new_fv);
	}
}

static gboolean
call_function(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *arg2,
							dfvm_value_t *arg3)
{
	df_func_def_t *funcdef;
	gboolean accum;
	df_cell_t *rp_return;
	guint32 arg_count;


	funcdef = arg1->value.funcdef;
	rp_return = &df->registers[arg2->value.numeric];
	arg_count = arg3->value.numeric;

	// Functions create a new value, so own it.
	df_cell_init(rp_return, TRUE);

	accum = funcdef->function(df->function_stack, arg_count, rp_return);
	return accum;
}

static void debug_op_error(const fvalue_t *v1, const fvalue_t *v2, const char *op, const char *msg)
{
	char *s1 = fvalue_to_debug_repr(NULL, v1);
	char *s2 = fvalue_to_debug_repr(NULL, v2);
	ws_noisy("Error: %s %s %s: %s", s1, op, s2, msg);
	g_free(s1);
	g_free(s2);
}

/* Used for temporary debugging only, don't leave in production code (at
 * a minimum WS_DEBUG_HERE must be replaced by another log level). */
static void _U_
debug_register(GSList *reg, guint32 num)
{
	wmem_strbuf_t *buf;
	GSList *l;
	char *s;

	buf = wmem_strbuf_new(NULL, NULL);

	wmem_strbuf_append_printf(buf, "Reg#%"G_GUINT32_FORMAT" = { ", num);
	for (l = reg; l != NULL; l = l->next) {
		s = fvalue_to_debug_repr(NULL, l->data);
		wmem_strbuf_append_printf(buf, "%s <%s>", s, fvalue_type_name(l->data));
		g_free(s);
		if (l->next != NULL) {
			wmem_strbuf_append(buf, ", ");
		}
	}
	wmem_strbuf_append_c(buf, '}');
	WS_DEBUG_HERE("%s", wmem_strbuf_get_str(buf));
	wmem_strbuf_destroy(buf);
}


typedef fvalue_t* (*DFVMBinaryFunc)(const fvalue_t*, const fvalue_t*, char **);

static void
mk_binary_internal(DFVMBinaryFunc func,
			const fvalue_t **fv_ptr1, size_t fv_count1,
			const fvalue_t **fv_ptr2, size_t fv_count2,
			df_cell_t *retval)
{
	fvalue_t *result;
	char *err_msg = NULL;

	for (size_t i = 0; i < fv_count1; i++) {
		for (size_t j = 0; j < fv_count2; j++) {
			result = func(fv_ptr1[i], fv_ptr2[j], &err_msg);
			if (result == NULL) {
				debug_op_error(fv_ptr1[i], fv_ptr2[i], "&", err_msg);
				g_free(err_msg);
				err_msg = NULL;
			}
			else {
				df_cell_append(retval, result);
			}
		}
	}
}

static void
mk_binary(dfilter_t *df, DFVMBinaryFunc func,
		dfvm_value_t *arg1, dfvm_value_t *arg2, dfvm_value_t *to_arg)
{
	df_cell_t *rp1, *rp2, *to_rp;
	const fvalue_t **fv_ptr1, **fv_ptr2;
	size_t fv_count1, fv_count2;

	if (arg1->type == REGISTER) {
		rp1 = &df->registers[arg1->value.numeric];
		fv_ptr1 = (const fvalue_t **)df_cell_array(rp1);
		fv_count1 = df_cell_size(rp1);
	}
	else if (arg1->type == FVALUE) {
		fv_ptr1 = (const fvalue_t **)&arg1->value.fvalue;
		fv_count1 = 1;
	}
	else {
		ws_assert_not_reached();
	}

	if (arg2->type == REGISTER) {
		rp2 = &df->registers[arg2->value.numeric];
		fv_ptr2 = (const fvalue_t **)df_cell_array(rp2);
		fv_count2 = df_cell_size(rp2);
	}
	else if (arg2->type == FVALUE) {
		fv_ptr2 = (const fvalue_t **)&arg2->value.fvalue;
		fv_count2 = 1;
	}
	else {
		ws_assert_not_reached();
	}

	to_rp = &df->registers[to_arg->value.numeric];
	df_cell_init(to_rp, TRUE);

	mk_binary_internal(func, fv_ptr1, fv_count1, fv_ptr2, fv_count2, to_rp);
	//debug_register(result, to_arg->value.numeric);
}

static void
mk_minus_internal(const fvalue_t **fv_ptr, size_t fv_count, df_cell_t *retval)
{
	fvalue_t *result;
	char *err_msg = NULL;

	for (size_t i = 0; i < fv_count; i++) {
		result = fvalue_unary_minus(fv_ptr[i], &err_msg);
		if (result == NULL) {
			ws_noisy("unary_minus: %s", err_msg);
			g_free(err_msg);
			err_msg = NULL;
		}
		else {
			df_cell_append(retval, result);
		}
	}
}

static void
mk_minus(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *to_arg)
{
	df_cell_t *rp1, *to_rp;
	const fvalue_t **fv_ptr1;
	size_t fv_count1;

	if (arg1->type == REGISTER) {
		rp1 = &df->registers[arg1->value.numeric];
		fv_ptr1 = (const fvalue_t **)df_cell_array(rp1);
		fv_count1 = df_cell_size(rp1);
	}
	else if (arg1->type == FVALUE) {
		fv_ptr1 = (const fvalue_t **)&arg1->value.fvalue;
		fv_count1 = 1;
	}
	else {
		ws_assert_not_reached();
	}

	to_rp = &df->registers[to_arg->value.numeric];
	df_cell_init(to_rp, TRUE);

	mk_minus_internal(fv_ptr1, fv_count1, to_rp);
}

static void
put_fvalue(dfilter_t *df, dfvm_value_t *arg1, dfvm_value_t *to_arg)
{
	fvalue_t *fv = arg1->value.fvalue;
	df_cell_t *to_rp = &df->registers[to_arg->value.numeric];
	df_cell_append(to_rp, fv);
	/* Memory is owned by the dfvm_value_t. */
	df_cell_init(to_rp, FALSE);
}

static void
stack_push(dfilter_t *df, dfvm_value_t *arg1)
{
	GPtrArray *arg;

	if (arg1->type == FVALUE) {
		arg = g_ptr_array_new();
		g_ptr_array_add(arg, arg1->value.fvalue);
	}
	else if (arg1->type == REGISTER) {
		arg = df_cell_ref(&df->registers[arg1->value.numeric]);
	}
	else {
		ws_assert_not_reached();
	}
	df->function_stack = g_slist_prepend(df->function_stack, arg);
}

static void
stack_pop(dfilter_t *df, dfvm_value_t *arg1)
{
	guint count = arg1->value.numeric;

	for (guint i = 0; i < count; i++) {
		/* Free top of stack data. */
		g_ptr_array_unref(df->function_stack->data);
		/* Remove top of stack. */
		df->function_stack = g_slist_delete_link(df->function_stack, df->function_stack);
	}
}

static gboolean
check_exists_finfos(proto_tree *tree, header_field_info *hfinfo, drange_t *range)
{
	GPtrArray *finfos;

	finfos = proto_get_finfo_ptr_array(tree, hfinfo->id);
	if (finfos == NULL || g_ptr_array_len(finfos) == 0) {
		return FALSE;
	}
	if (range == NULL) {
		return TRUE;
	}
	return filter_finfo_fvalues(NULL, finfos, range, FALSE) > 0;
}

static gboolean
check_exists(proto_tree *tree, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	header_field_info	*hfinfo;
	drange_t		*range = NULL;

	hfinfo = arg1->value.hfinfo;
	if (arg2)
		range = arg2->value.drange;

	while (hfinfo) {
		if (check_exists_finfos(tree, hfinfo, range)) {
			return TRUE;
		}
		hfinfo = hfinfo->same_name_next;
	}

	return FALSE;
}

gboolean
dfvm_apply(dfilter_t *df, proto_tree *tree)
{
	int		id, length;
	gboolean	accum = TRUE;
	dfvm_insn_t	*insn;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3 = NULL;

	ws_assert(tree);

	length = df->insns->len;

	for (id = 0; id < length; id++) {

	  AGAIN:
		insn = g_ptr_array_index(df->insns, id);
		arg1 = insn->arg1;
		arg2 = insn->arg2;
		arg3 = insn->arg3;

		switch (insn->op) {
			case DFVM_CHECK_EXISTS:
				accum = check_exists(tree, arg1, NULL);
				break;

			case DFVM_CHECK_EXISTS_R:
				accum = check_exists(tree, arg1, arg2);
				break;

			case DFVM_READ_TREE:
				accum = read_tree(df, tree, arg1, arg2, NULL);
				break;

			case DFVM_READ_TREE_R:
				accum = read_tree(df, tree, arg1, arg2, arg3);
				break;

			case DFVM_READ_REFERENCE:
				accum = read_reference(df, arg1, arg2, NULL);
				break;

			case DFVM_READ_REFERENCE_R:
				accum = read_reference(df, arg1, arg2, arg3);
				break;

			case DFVM_PUT_FVALUE:
				put_fvalue(df, arg1, arg2);
				break;

			case DFVM_CALL_FUNCTION:
				accum = call_function(df, arg1, arg2, arg3);
				break;

			case DFVM_STACK_PUSH:
				stack_push(df, arg1);
				break;

			case DFVM_STACK_POP:
				stack_pop(df, arg1);
				break;

			case DFVM_SLICE:
				mk_slice(df, arg1, arg2, arg3);
				break;

			case DFVM_LENGTH:
				mk_length(df, arg1, arg2);
				break;

			case DFVM_ALL_EQ:
				accum = all_test(df, fvalue_eq, arg1, arg2);
				break;

			case DFVM_ANY_EQ:
				accum = any_test(df, fvalue_eq, arg1, arg2);
				break;

			case DFVM_ALL_NE:
				accum = all_test(df, fvalue_ne, arg1, arg2);
				break;

			case DFVM_ANY_NE:
				accum = any_test(df, fvalue_ne, arg1, arg2);
				break;

			case DFVM_ALL_GT:
				accum = all_test(df, fvalue_gt, arg1, arg2);
				break;

			case DFVM_ANY_GT:
				accum = any_test(df, fvalue_gt, arg1, arg2);
				break;

			case DFVM_ALL_GE:
				accum = all_test(df, fvalue_ge, arg1, arg2);
				break;

			case DFVM_ANY_GE:
				accum = any_test(df, fvalue_ge, arg1, arg2);
				break;

			case DFVM_ALL_LT:
				accum = all_test(df, fvalue_lt, arg1, arg2);
				break;

			case DFVM_ANY_LT:
				accum = any_test(df, fvalue_lt, arg1, arg2);
				break;

			case DFVM_ALL_LE:
				accum = all_test(df, fvalue_le, arg1, arg2);
				break;

			case DFVM_ANY_LE:
				accum = any_test(df, fvalue_le, arg1, arg2);
				break;

			case DFVM_BITWISE_AND:
				mk_binary(df, fvalue_bitwise_and, arg1, arg2, arg3);
				break;

			case DFVM_ADD:
				mk_binary(df, fvalue_add, arg1, arg2, arg3);
				break;

			case DFVM_SUBTRACT:
				mk_binary(df, fvalue_subtract, arg1, arg2, arg3);
				break;

			case DFVM_MULTIPLY:
				mk_binary(df, fvalue_multiply, arg1, arg2, arg3);
				break;

			case DFVM_DIVIDE:
				mk_binary(df, fvalue_divide, arg1, arg2, arg3);
				break;

			case DFVM_MODULO:
				mk_binary(df, fvalue_modulo, arg1, arg2, arg3);
				break;

			case DFVM_NOT_ALL_ZERO:
				accum = !all_test_unary(df, fvalue_is_zero, arg1);
				break;

			case DFVM_ALL_CONTAINS:
				accum = all_test(df, fvalue_contains, arg1, arg2);
				break;

			case DFVM_ANY_CONTAINS:
				accum = any_test(df, fvalue_contains, arg1, arg2);
				break;

			case DFVM_ALL_MATCHES:
				accum = all_matches(df, arg1, arg2);
				break;

			case DFVM_ANY_MATCHES:
				accum = any_matches(df, arg1, arg2);
				break;

			case DFVM_ALL_IN_RANGE:
				accum = all_in_range(df, arg1, arg2, arg3);
				break;

			case DFVM_ANY_IN_RANGE:
				accum = any_in_range(df, arg1, arg2, arg3);
				break;

			case DFVM_UNARY_MINUS:
				mk_minus(df, arg1, arg2);
				break;

			case DFVM_NOT:
				accum = !accum;
				break;

			case DFVM_RETURN:
				free_register_overhead(df);
				return accum;

			case DFVM_IF_TRUE_GOTO:
				if (accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;

			case DFVM_IF_FALSE_GOTO:
				if (!accum) {
					id = arg1->value.numeric;
					goto AGAIN;
				}
				break;
		}
	}

	ws_assert_not_reached();
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
