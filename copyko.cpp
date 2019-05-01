#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <stack>
#include <algorithm>
#include <filesystem>
#include <ext/stdio_filebuf.h>
#include <cstring>
#include <cassert>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <libintl.h>
#include <getopt.h>
#include <error.h>
#include <glob.h>
#include <sys/utsname.h>
#define _(STRING) gettext(STRING)

/* Used terms:
 * Module name (ip6_tables)
 * Module filename (ip6_tables.ko)
 * Module filename with path (kernel/net/ipv6/netfilter/ip6_tables,
 * 	path is relative to source or destination directory) */

using namespace std;
namespace fs = std::filesystem;

struct Ko_info {
	vector<string> deps; // List of module names required for this module
	set<string> pulled_by; // List of user-defined module names which pull this file
	const string * path; // Relative path
	bool su; // Module selected by user (in argv[])
};

fs::path srcdir; // Modules source directory
fs::path dstdir; // Modules destination directory
fs::path fwsrc; // Firmware source directory
fs::path fwdst; // Firmware destination directory
map<string, string> all_ko; // Map module names to their filenames with path
map<string, Ko_info> ko_list; // List of modules to copy and their info
set<string> firmware; // Firmware filenames to copy (with relative path)
bool try_link = false; // Should program try to make hard link instead of copy files
bool verbose = false;

static constexpr std::string_view operator "" _s (const char* str, const size_t size)
{
	return std::string_view(str, size);
}

// Split string using ',' as delimiter
vector<string_view> split_sv(string_view strv)
{
	vector<string_view> output;
	size_t first = 0;
	while (first < strv.size())
	{
		size_t second = strv.find_first_of(',', first);
		if (first != second)
			output.emplace_back(strv.substr(first, second-first));
		if (second == string_view::npos)
			break;
		first = second + 1;
	}
	return output;
}

static void show_version()
{
	cout << _("copyko 0.1\nCopyright (C) 2019 Oshepkov Kosntantin\n"
	"License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n");
	exit(0);
}

static void show_help()
{
	cout << _("Usage: copyko [OPTION] <module> ... <dest>\n"
			"Copy kernel modules (ko-files) and its' dependencies to <dest> directory\n"
			"The program is useful when creating Live CD\n\n"
			"Options:\n"
			"  -f, --from=FROM  directory to search kernel modules\n"
			"      --fwsrc=FROM directory to search firmware\n"
			"      --fwdst=TO   directory to store firmware\n"
			"  -l, --link       try to make hard links instead of copy files\n"
			"  -v, --verbose    explain what is being done\n"
			"      --help       display this help and exit\n"
			"      --version    output version information and exit\n"
			"Report bugs to: oks-mgn@mail.ru\n"
			"copyko home page: <NOT YET, TODO>\n"
			"General help using GNU software: <https://www.gnu.org/gethelp/>\n");
	exit(0);
}

// Returns module names as written by user in argv, also fill global variables
static vector<string> parse_args(int argc, char ** argv)
{
	vector<string> res;
	string srcdir_s, dstdir_s, fwsrc_s, fwdst_s;
	static const struct option longOpts[] = {
		{"help", no_argument, 0, 0},
		{"version", no_argument, 0, 0},
		{"fwsrc", required_argument, 0, 2},
		{"fwdst", required_argument, 0, 3},
		{"verbose", no_argument, 0, 'v'},
		{"link", no_argument, 0, 'l'},
		{"from", required_argument, 0, 'f'},
		{0, no_argument, 0, 0}
	};
	int longIndex = 0;

	int c;
	while ((c = getopt_long(argc, argv, "-vlf:", longOpts, &longIndex)) != -1) {
		switch (c) {
		case '?':
			show_help();
		case 'f':
			srcdir_s = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'l':
			try_link = true;
			break;
		case 2:
			fwsrc_s = optarg;
			break;
		case 3:
			fwdst_s = optarg;
			break;
		case 0:
			if (!strcmp(optarg, "--help"))
				show_help();
			else if (!strcmp(optarg, "--version"))
				show_version();
			else
				error(1, 0, _("Unrecognized option %s"), optarg);
		default:
			res.emplace_back(optarg);
		}
	}

	if (srcdir_s.empty()) {
		struct utsname buffer;
		if (uname(&buffer) != 0)
			error(1, errno, "Uname error");
		srcdir_s = string("/lib/modules/"_s) + buffer.release;
	}
	srcdir = move(srcdir_s);

	if (res.size() < 2)
		show_help();
	dstdir = res.back();
	res.pop_back();

	fwsrc = fwsrc_s.empty() ?
		srcdir.parent_path().parent_path() / "firmware"_s :
		fs::path(move(fwsrc_s));

	fwdst = fwdst_s.empty() ?
		dstdir.parent_path().parent_path() / "firmware"_s :
		fs::path(move(fwdst_s));

	if (verbose)
		cout << _("Source directory is ") << srcdir << '\n'
			<< _("Source firmware directory is ") << fwsrc << '\n'
			<< _("Destination directory is ") << dstdir << '\n'
			<< _("Destination firmware directory is ") << fwdst << '\n';

	sort(res.begin(), res.end());
	res.erase(unique(res.begin(), res.end()), res.end());
	return res;
}

// Returns all modules in srcdir: module name => module filename with relative path
map<string, string> find_all_ko_files()
{
	map<string, string> res;
	for(auto& it : fs::recursive_directory_iterator(srcdir, fs::directory_options::skip_permission_denied)) {
		if (!it.is_regular_file()) continue;
		fs::path pth =  it.path();
		if (pth.extension() != ".ko") continue;
		string basename = pth.stem();
		auto p = res.insert_or_assign(move(basename), fs::relative(pth, srcdir));
		if (!p.second)
			cerr << _("There are more than one module with same name ") << basename << '\n';
	}
	return res;
}

/* Returns dependencies for module-filename-with-path
 * Also fills global "firmware" variable
 * Assume that filenames don't contain commas (,) and whitespaces (' ', '\t', ...) */
static vector<string> read_ko(const string& module)
{
	int pfd[2];
	if (pipe(pfd)) error(1, errno, "pipe error");
	pid_t pid = fork();
	if (pid == -1) error(1, errno, "fork error");

	if (!pid) {
		if (dup2(pfd[1], STDOUT_FILENO) == -1) error(1, errno, "dup2() error");
		close(pfd[1]);
		close(pfd[0]);

		char * args[3] = {(char *)"modinfo", (char *)module.c_str(), NULL};
		execvp(args[0], args);
		error(1, errno, _("Can't run %s"), args[0]);
	}
	close(pfd[1]);

	__gnu_cxx::stdio_filebuf<char> buf(pfd[0], std::ios::in);
	istream is(&buf);
	string line;
	vector<string> res;
	bool depends_found = false;
	while(getline(is, line)) {
		string lh, lv;
		istringstream(line) >> lh >> lv;
		if (lh == "depends:"_s) {
			vector<string_view> names = split_sv(lv);
			res.reserve(names.size());
			for (string_view f : names) res.emplace_back(f);
			depends_found = true;
		} else if (lh == "firmware:"_s) {
			vector<string_view> names = split_sv(lv);
			for (string_view f : names) firmware.emplace(f);
		}
	}
	assert(depends_found);
	return res;
}

// Add module name and it's dependencies to ko_list
static void process_module(const string& name)
{
	auto pth = all_ko.find(name);
	if (pth == all_ko.end()) {
		cerr << name << _(" not found") << '\n';
		return;
	}
	auto p = ko_list.try_emplace(name);
	if (!p.second) return;
	Ko_info& ki = p.first->second;
	ki.path = &pth->second;
	ki.deps = read_ko(srcdir / pth->second);
	for (const string& fn : ki.deps)
		process_module(fn);
}

/* Mark module that it is autopulled by user_module, do it reccursively.
 * module - module name to mark
 * user_module - module name from command line
 * rec_lev - infinite reccursion protection */
static void mark_dep_req(const string& module, const string& user_module, int rec_lev = 0)
{
	if (rec_lev > 1024) {
		cerr << _("Dependency tree is too deep") << '\n';
		return;
	}
	Ko_info& ki = ko_list[module];
	ki.pulled_by.insert(user_module);
	for (const string& n : ki.deps)
		mark_dep_req(n, user_module, rec_lev + 1);
}

static void mark_dep(const string& module)
{
	// Assume that records of module and it's dependencies exist
	// Also assume that dependencies does not have infinite loops
	Ko_info& ki = ko_list[module];
	ki.su = true;
	for (const string& n : ki.deps)
		mark_dep_req(n, module);
}

// Also create destination directory. Try to make hard link if global flag set.
static void my_copy_file(const fs::path& src, const fs::path& dst)
{
	error_code ec;
	if (verbose)
		cout << src << " => "_s << dst << '\n';

	fs::path dstd = dst.parent_path();
	fs::create_directories(dstd, ec);
	if (ec && ec != errc::file_exists)
		error(0, errno, _("Can't create directory %s"), dstd.c_str());

	if (try_link) {
		static bool errflag = false;
		fs::create_hard_link(src, dst, ec);
		if (ec && ec != errc::file_exists && !errflag) {
			error(0, errno, _("Can't make hard link for file %s"), src.c_str());
			errflag = true;
		}
	}
	fs::copy_file(src, dst, ec);
	if (ec && ec != errc::file_exists)
		error(0, errno, _("Can't copy %s to %s"),
			src.c_str(),
			dst.c_str());
}

static void copy_modules()
{
	for (auto [mn, mi] : ko_list) { //module name, module info
		assert(mi.path);
		fs::path src = srcdir / *mi.path;
		fs::path dst = dstdir / *mi.path;
		my_copy_file(src, dst);
	}
}

static void copy_firmware()
{
	for (const string& fn : firmware) {
		fs::path src = fwsrc / fn;
		fs::path dst = fwdst / fn;
		my_copy_file(src, dst);
	}
}

// Show info if some module requested by user is pulled by other module
static void show_autoinstalled()
{
	bool flg = false;
	for (auto [mn, ki] : ko_list) {
		if (ki.su && !ki.pulled_by.empty()) {
			cout << _("Module ") << mn << _(" is dependency for");
			for (const string& s : ki.pulled_by)
				cout << ' ' << s;
			cout << '\n';
			flg = true;
		}
	}
	if (flg)
		cout << _("You can omit dependency modules because they are autocopied by other modules.") << '\n';
}

int main(int argc, char ** argv)
{
	setlocale(LC_ALL, "");
	bindtextdomain("copyko", DATAROOTDIR "/locale");
	textdomain("copyko");
	vector<string> ko_files = parse_args(argc, argv);
	all_ko = find_all_ko_files();
	for (const string& f: ko_files)
		process_module(f);
	copy_modules();
	copy_firmware();
	if (verbose) {
		for (const string& f: ko_files)
				mark_dep(f);
		show_autoinstalled();
	}
}
