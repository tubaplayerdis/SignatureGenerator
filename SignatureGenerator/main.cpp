#define _SILENCE_ALL_CXX20_DEPRECATION_WARNINGS

#include <ida.hpp>
#include <idp.hpp>
#include <demangle.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <windows.h>

// Forward declarations
std::string make_cstyle_macro_name(std::string demangled);
std::string remove_return_type_and_calling_convention(std::string name);
std::string remove_parameters(std::string name);

/**
 * @brief Helper function to trim leading and trailing underscores from a string.
 */
static std::string trim_underscores(const std::string& str)
{
    size_t first = str.find_first_not_of('_');
    if (first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of('_');
    return str.substr(first, (last - first + 1));
}

/**
 * @brief Demangles a function name and returns its C-style macro format.
 * * @param func_name Raw or mangled name of the function.
 * @return std::string The converted UPPERCASE_WITH_UNDERSCORES macro name.
 */
static std::string make_macro_name(const std::string& func_name)
{
    char answer_buffer[2048];
    std::string demangled;

    // Calls the legacy demangle function: 
    // int32 demangle(char *answer, uint answer_length, const char *str, uint32 disable_mask);
    // Passing 0 to disable_mask ensures standard demangling rules are applied.
    int32 result = demangle(answer_buffer, sizeof(answer_buffer), func_name.c_str(), 0);

    if (result > 0)
    {
        demangled = answer_buffer;
    }
    else
    {
        // Fallback to the raw function name if demangling fails
        demangled = func_name;
    }

    return make_cstyle_macro_name(demangled);
}

/**
 * @brief Cleans and converts a demangled string to a standard macro string.
 */
static std::string make_cstyle_macro_name(std::string demangled)
{
    // Remove return type and calling conventions
    std::string name = remove_return_type_and_calling_convention(demangled);

    // Remove parameters
    name = remove_parameters(name);

    // Replace all non-alphanumeric characters with underscores
    std::regex non_alnum("[^a-zA-Z0-9]");
    name = std::regex_replace(name, non_alnum, "_");

    // Clean up continuous multiple underscores into a single underscore
    std::regex multi_underscores("_+");
    name = std::regex_replace(name, multi_underscores, "_");

    // Trim external underscores
    name = trim_underscores(name);

    // Convert string to uppercase
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return std::toupper(c);
        });

    // Ensure it starts with a letter
    if (name.empty())
    {
        name = "UNKNOWN_MACRO";
    }
    else if (!std::isalpha(static_cast<unsigned char>(name[0])))
    {
        name = "MACRO_" + name;
    }

    return name;
}

/**
 * @brief Strip common calling conventions and leading specifiers.
 */
static std::string remove_return_type_and_calling_convention(std::string name)
{
    std::vector<std::regex> calling_conventions = {
        std::regex("__fastcall\\s+"),
        std::regex("__cdecl\\s+"),
        std::regex("__stdcall\\s+"),
        std::regex("__thiscall\\s+"),
        std::regex("__vectorcall\\s+")
    };

    for (const auto& pattern : calling_conventions)
    {
        name = std::regex_replace(name, pattern, "");
    }

    // Remove return type if it's at the beginning (void, int, etc.)
    std::regex return_type("^\\w+\\s+");
    name = std::regex_replace(name, return_type, "");

    // Trim outer whitespace safely
    size_t first = name.find_first_not_of(" \t\r\n");
    if (first != std::string::npos)
    {
        size_t last = name.find_last_not_of(" \t\r\n");
        name = name.substr(first, (last - first + 1));
    }

    return name;
}

/**
 * @brief Strip function parameters completely.
 */
static std::string remove_parameters(std::string name)
{
    std::regex params_re("\\([^)]*\\)");
    return std::regex_replace(name, params_re, "");
}

static std::string generate_signature_with_wildcards(ea_t func_ea, ea_t length = 25)
{
    // Fetch the function pointer from the EA
    func_t* func = get_func(func_ea);
    if (func == nullptr)
    {
        msg("SigGen: func was null!");
        return "";
    }

    ea_t start = func->start_ea;
    ea_t end = min(start + length, func->end_ea);

    std::vector<uint8_t> bytes_list;
    std::vector<char> mask_list;

    ea_t ea = start;
    while (ea < end)
    {
        insn_t insn;
        int inslen = decode_insn(&insn, ea);
        if (inslen <= 0)
        {
            break;
        }

        // Collect raw bytes for the decoded instruction
        for (int i = 0; i < inslen; i++)
        {
            bytes_list.push_back(get_byte(ea + i));
            mask_list.push_back('x'); // 'x' means keep the byte as-is
        }

        // Mask relocatable operands
        for (int i = 0; i < UA_MAXOP; ++i)
        {
            const op_t& op = insn.ops[i];
            if (op.type == o_void)
                break;

            // Check if the operand is an immediate, address, memory reference, or displacement
            if (op.type == o_imm || op.type == o_near ||
                op.type == o_far || op.type == o_mem ||
                op.type == o_displ)
            {
                int offb = op.offb; // Offset of the operand bytes inside the instruction

                // Determine the size of the operand data type
                size_t size = get_dtype_size(op.dtype);
                if (size == 0)
                {
                    size = inf_is_64bit() ? 8 : 4;
                }

                // Apply the wildcards to the specific bytes making up the operand
                for (int j = offb; j < offb + (int)size; ++j)
                {
                    if (j >= 0 && j < inslen)
                    {
                        size_t global_index = bytes_list.size() - inslen + j;
                        if (global_index < mask_list.size())
                        {
                            mask_list[global_index] = '?';
                        }
                    }
                }
            }
        }

        ea += inslen;
    }

    // Construct the final space-separated signature string
    std::ostringstream ss;

    for (size_t i = 0; i < bytes_list.size(); ++i)
    {
        if (mask_list[i] == '?')
        {
            ss << "??";
        }
        else
        {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)bytes_list[i];
        }

        if (i < bytes_list.size() - 1)
        {
            ss << " ";
        }
    }

    return ss.str();
}

static sval_t desired_sig_length()
{
	constexpr sval_t default_val = 25;
	sval_t val = default_val;
	ask_long(&val, "Enter signature length in bytes");
	if (val > 0) return val; else return default_val;
}

static bool CopyToClipboard(const std::string& text) {
    // 1. Open the system clipboard and associate it with the current process
    if (!OpenClipboard(nullptr)) {
        return false;
    }

    // 2. Clear the current clipboard contents
    if (!EmptyClipboard()) {
        CloseClipboard();
        return false;
    }

    // 3. Calculate size and allocate moveable global memory block
    size_t size = text.length() + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
    if (!hMem) {
        CloseClipboard();
        return false;
    }

    // 4. Lock the memory block to get a physical system pointer
    char* pMem = static_cast<char*>(GlobalLock(hMem));
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    // 5. Copy the character array data into the locked block
    memcpy(pMem, text.c_str(), size);

    // 6. Unlock the global block
    GlobalUnlock(hMem);

    // 7. Pass ownership of the memory object to the clipboard using CF_TEXT
    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem); // Free memory only if SetClipboardData fails
        CloseClipboard();
        return false;
    }

    // 8. Always close the clipboard when done so other apps can access it
    CloseClipboard();
    return true;
}

constexpr auto ACTION_SIG = "siggen:generate_sig";

class SigGenHandler : public action_handler_t
{
public:
	virtual int idaapi activate(action_activation_ctx_t* ctx) override
	{
		auto ea = ctx->cur_ea;
		auto func = get_func(ea);

		if (!func)
		{
			msg("SigGen: No function at cursor!\n");
			return 0;
		}

		qstring func_name;
		get_func_name(&func_name, ea);

		sval_t sig_len = desired_sig_length();

        std::string macro_name = make_macro_name(std::string(func_name.c_str()));
        std::string signature = generate_signature_with_wildcards(ea, sig_len);

        CopyToClipboard(signature);

        msg("Signature copied for: %s\nSignature: %s", macro_name.c_str(), signature.c_str());

        return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t* ctx) override
	{
		return get_func(ctx->cur_ea) != nullptr ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
	}
};

/**
 * @brief Hook callback that receives user interface events from IDA.
 */
static ssize_t idaapi ui_callback(void* user_data, int notification_code, va_list va)
{
    // Check if IDA has finished populating a context/popup menu
    if (notification_code == ui_finish_populating_widget_popup)
    {
        // Extract arguments passed via the va_list
        TWidget* widget = va_arg(va, TWidget*);
        TPopupMenu* popup = va_arg(va, TPopupMenu*);

        // Query the widget type (e.g., Disassembly, Pseudocode)
        twidget_type_t widget_type = get_widget_type(widget);

        if (widget_type == BWN_DISASM || widget_type == BWN_PSEUDOCODE)
        {
            // Attach the actions to the right-click context menu
            attach_action_to_popup(widget, popup, ACTION_SIG);
        }
    }

    // Return 0 to allow other plugins/IDA to continue processing UI events
    return 0;
}

static void RegisterActions()
{

	register_action(action_desc_t
	{
		.name = ACTION_SIG,
		.label = "Generate Sig with Wildcards(SigGen)",
		.handler = new SigGenHandler(),
		.tooltip = "Generate Signature with ?? wildcards then copy to clipboard",
		.icon = -1,
	});

    hook_to_notification_point(HT_UI, ui_callback, nullptr);
}

static void UnregisterActions()
{
    unregister_action(ACTION_SIG);
    unhook_from_notification_point(HT_UI, ui_callback, nullptr);
}

// Define the class that inherits from plugmod_t
class SigGenPlugin : public plugmod_t
{
public:
	// Constructor
	SigGenPlugin()
	{
        RegisterActions();
		msg("Registered SigGen Actions!\n");
	}

	// Destructor
	virtual ~SigGenPlugin()
	{
        UnregisterActions();
		msg("Unregistered SigGen Actions!\n");
	}

	// Method that gets called when the plugin is activated
	virtual bool idaapi run(size_t arg) override
	{
		return true;
	}
};

static plugmod_t* idaapi init(void)
{
	return new SigGenPlugin();
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // plugin flags
  init,                 // initialize
  nullptr,              // terminate. this pointer can be nullptr
  nullptr,              // invoke the plugin
  "Signature generator that adds popup menu actions",              // long comment about the plugin
  "Right-click a function -> Generate Signature with ?? wildcards",              // multiline help about the plugin
  "SigGen",		// the preferred short name of the plugin
  ""					// the preferred hotkey to run the plugin
};