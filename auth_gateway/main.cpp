#include <cstdlib>
#include <sys/time.h>
#include <sys/resource.h>

#include <iostream>
#include <thread>

#include <boost/program_options.hpp>
#include <boost/ref.hpp>

#include "common.hpp"
#include "application.hpp"

static int program_option(boost::program_options::variables_map&, int, char *[]);


int main(int argc, char *argv[]) {
	neosystem::util::set_rlimit_core();

	boost::program_options::variables_map vm;
	int ret = program_option(vm, argc, argv);
	if (ret == 1) {
		return 0;
	} else if (ret ==2) {
		return 1;
	}

	if (poppo::auth_gateway::application::static_member_init(vm["conf"].as<std::string>()) == false) {
		return 1;
	}

	poppo::auth_gateway::application app;
	app.run();
	return 0;
}

static int program_option(boost::program_options::variables_map& vm, int argc, char *argv[]) {
	boost::program_options::options_description opt("options");
	opt.add_options()
		("help,h", "help")
		("version,v", "show version")
		("conf,c", boost::program_options::value<std::string>(), "config file")
		;
	try {
		store(boost::program_options::parse_command_line(argc, argv, opt), vm);
		notify(vm);
	} catch (const boost::program_options::error& e) {
		std::cout << e.what() << std::endl;
		std::cout << opt << std::endl;
		return 1;
	}
	if (vm.count("help")) {
		std::cout << opt << std::endl;
		return 2;
	}
	if (vm.count("version")) {
		poppo::auth_gateway::application::show_version();
		return 2;
	}
	if (vm.count("conf") == 0) {
		std::cout << opt << std::endl;
		return 1;
	}
	return 0;
}
