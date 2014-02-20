#ifndef _PE_H_
#define _PE_H_

#include <stdio.h>

#include <string>
#include <vector>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#include "pe-parse/parser-library/parse.h"


namespace sg {

typedef struct _section
{
	VA base_address;
	std::string name;
	boost::uint32_t size;
} section;

typedef boost::shared_ptr<section> p_section;

int add_section(void* target_object,
		VA base,
		std::string& secname,
		image_section_header s,
		bounded_buffer* data);

bool same_name(const std::string& name, p_section sec) {
	return name == sec->name;
}

class PE
{

public:
	PE(const std::string& path)
		: _path(path)
	{
		parsed_pe *p = ParsePEFromFile(_path.c_str());
		if (p == NULL) {
			return;
		}

		IterSec(p, add_section, this);

		DestructParsedPE(p);
	}

	std::vector<p_section>& get_sections()
	{
		return _sections;
	}

	p_section get_section(const std::string& name)
	{
		std::vector<p_section>::iterator it = std::find_if(_sections.begin(), _sections.end(), boost::bind(&sg::same_name, ".rsrc", _1));
		if (it == _sections.end()) {
			return p_section();
		}
		else {
			return *it;
		}
	}

	size_t get_filesize()
	{
		FILE* f = fopen(_path.c_str(), "r");
		size_t res = 0;
		if (f == NULL) {
			return res;
		}
		fseek(f, 0, SEEK_END);
		res = ftell(f);
		fclose(f);
		return res;
	}

private:
	std::string _path;
	std::vector<p_section> _sections;
};

int add_section(void* target_object,
		VA base,
		std::string& secname,
		image_section_header s,
		bounded_buffer* data)
{
	p_section sect(new section);

	sect->base_address = base;
	sect->name = secname;
	sect->size = data->bufLen;
	((PE*) target_object)->get_sections().push_back(sect);

	delete data;
	return 0;
}


} /* !namespace sg */

#endif /* !_PE_H_ */
