#include "yara_wrapper.h"

namespace yara
{

int Yara::_instance_count = 0;

Yara::~Yara()
{
	if (_compiler != NULL) {
		yr_compiler_destroy(_compiler);
	}
	if (_rules != NULL) {
		yr_rules_destroy(_rules);
	}

	--_instance_count;
	if (_instance_count == 0) {
		yr_finalize();
	}
}

// ----------------------------------------------------------------------------

bool Yara::load_rules(const std::string& rule_filename)
{
	if (_current_rules == rule_filename) {
		return true;
	}

	bool res = false;
	int retval = yr_rules_load(rule_filename.c_str(), &_rules);
	if (retval != ERROR_SUCCESS && retval != ERROR_INVALID_FILE)
	{
		std::cerr << "Could not load yara rules. (Yara Error 0x" << std::hex << retval << ")" << std::endl;
		return false;
	}

	if (retval == ERROR_INVALID_FILE)
	{
		if (yr_compiler_create(&_compiler) != ERROR_SUCCESS) {
			return false;
		}
		FILE* rule_file = fopen(rule_filename.c_str(), "r");
		if (rule_file == NULL) {
			return false;
		}
		retval = yr_compiler_add_file(_compiler, rule_file, NULL);
		if (retval != ERROR_SUCCESS) {
			goto END;
		}
		retval = yr_compiler_get_rules(_compiler, &_rules);
		if (retval != ERROR_SUCCESS) {
			goto END;
		}
		res = true;
		_current_rules = rule_filename;
		END:
		if (rule_file != NULL) {
			fclose(rule_file);
		}
	}
	return res;
}

// ----------------------------------------------------------------------------

matches Yara::scan_bytes(std::vector<boost::uint8_t>& bytes)
{
	matches res;
	if (_rules == NULL || bytes.size() == 0)
	{
		if (_rules == NULL) {
			std::cerr << "Error: No Yara rules loaded!" << std::endl;
		}
		return res;
	}

	// Yara setup done. Scan the file.
	yr_rules_scan_mem(_rules,
		&bytes[0],			  // The bytes to scan
		bytes.size(),			  // Number of bytes
		get_match_metadata,
		&res,					  // The vector to fill
		FALSE,                  // We don't want a fast scan.
		0);                     // No timeout)

	return res;
}

// ----------------------------------------------------------------------------

int get_match_metadata(int message, YR_RULE* rule, void* data)
{
	matches* target = NULL;
	YR_META* meta = NULL;
	pmatch m;

	switch (message)
	{
		case CALLBACK_MSG_RULE_MATCHING:
			target = (matches*)data; // I know what I'm doing.
			meta = rule->metas;
			m = pmatch(new match);
			while (!META_IS_NULL(meta))
			{
				m->operator[](std::string(meta->identifier)) = meta->string;
				++meta;
			}
			target->push_back(m);
			return CALLBACK_CONTINUE;

		case CALLBACK_MSG_RULE_NOT_MATCHING:
			return CALLBACK_CONTINUE;
	}
	return CALLBACK_ERROR;
}

} // !namespace yara