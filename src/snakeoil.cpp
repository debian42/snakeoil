#include "conscolor.h"
#include "fileiter.h"
#include <iomanip>
#include <ImageHlp.h>
#include <vector>
// Frank Peters 2012
#pragma comment(lib,"imagehlp.lib") 

static char* getCmdOption(char ** begin, char ** end, const std::string & option)
{
	char ** itr = std::find(begin, end, option);
	if (itr != end)
		return *itr;
	return 0;
}

static bool DEBUG   = false;
static bool R_SLR   = false;
static bool A_SLR   = false;
static bool R_DEP   = false;
static bool A_DEP   = false;
static bool R_INTG  = false;
static bool A_INTG  = false;
static bool R_CERT  = false;
static bool A_LADDR = false;
static bool R_LADDR = false;


static void printError(std::string const& txt) {
	DWORD lastError = GetLastError();
	const int SIZE = 512;
	char buf[SIZE + 1] = { 0 };
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, SIZE, NULL);
	std::cerr << ColorConsole::red << txt << ": (" << lastError << ") " << buf << ColorConsole::lightGray << "\n";
}

namespace {
	struct retStruct {
		struct patched {
			int numCerts = 0;
			bool aslr_s = false;
			bool aslr_r = false;
			bool dep_s = false;
			bool dep_r = false;
			bool intg_s = false;
			bool intg_r = false;
			bool laddr_s = false;
			bool laddr_r = false;
		}p;
		long long baseaddress = 0;
		int numCerts = 0;
		bool aslr = false;
		bool dep = false;
		bool intg = false;
		bool laddr = false;
		bool okay = false;
	};
}

static retStruct work(std::string const &filename, bool modify)
{
	retStruct retVal;
	LOADED_IMAGE PE;
	DWORD num_certs = 0;
	BOOL ok = MapAndLoad(filename.c_str(), 0, &PE, 0, !modify);
	if (ok)
	{
		retVal.aslr = !! (PE.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
#ifdef _WIN64
		if (PE.FileHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
			retVal.baseaddress = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&PE.FileHeader->OptionalHeader)->ImageBase;
		else
			retVal.baseaddress = PE.FileHeader->OptionalHeader.ImageBase;
#else
		if (PE.FileHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
			retVal.baseaddress = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&PE.FileHeader->OptionalHeader)->ImageBase;
		else
			retVal.baseaddress = PE.FileHeader->OptionalHeader.ImageBase;
#endif
		retVal.dep = !! (PE.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT);
		retVal.intg = !! (PE.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);	
		retVal.laddr = !!(PE.FileHeader->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE);
		if (A_SLR) {
			PE.FileHeader->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
			retVal.p.aslr_s = retVal.aslr == false ? true : false;
		}
		if (R_SLR) {
			PE.FileHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
			retVal.p.aslr_r = retVal.aslr == true ? true : false;
		}

		if (A_DEP) {
			PE.FileHeader->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
			retVal.p.dep_s = retVal.dep == false ? true : false;
		}
		if (R_DEP) {
			PE.FileHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
			retVal.p.dep_r = retVal.dep == true ? true : false;
		}
		if (A_INTG) {
			PE.FileHeader->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
			retVal.p.intg_s = retVal.intg == false ? true : false;
		}
		if (R_INTG) {
			PE.FileHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
			retVal.p.intg_r = retVal.intg == true? true : false;
		}
		if (A_LADDR) {
			PE.FileHeader->FileHeader.Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
			retVal.p.laddr_s = retVal.laddr == false ? true : false;
		}
		if (R_LADDR) {
			PE.FileHeader->FileHeader.Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;
			retVal.p.laddr_r = retVal.laddr == true ? true : false;
		}
		HANDLE h = PE.hFile;
		ok = ImageEnumerateCertificates(h, CERT_SECTION_TYPE_ANY, &num_certs, NULL, 0);
		retVal.numCerts = num_certs;
		retVal.p.numCerts = retVal.numCerts;
		if (!ok) {
			if (DEBUG)
				printError("ImageEnumerateCertificates(" + filename + ")");
		}
		if (R_CERT) {
			if (num_certs > 0) {
				ok = ImageRemoveCertificate(h, 0);
				if (!ok) {
					printError("ImageRemoveCertificate(" + filename + ")");
				}
				else {
					retVal.p.numCerts = num_certs -1;
				}
			}
			else if (DEBUG) {
				std::cerr << ColorConsole::red << "No cert found in " << filename << ColorConsole::lightGray << std::endl;
			}
		}
		retVal.okay = true;
		ok = UnMapAndLoad(&PE);
		if (!ok) {
			printError("UnMapAndLoad(" + filename + ")");
		}
	}
	else {
		if (DEBUG) {
			std::string error = "MapAndLoad(" + filename + ")";
			printError(error);			
		}
	}
	return retVal;
}



static inline std::string truncate(std::string str, size_t width)
{
	auto l = str.length();
	if (l > width) {
		if (width > 3 )
			return  "..." + str.substr(l-(width - 3), (width-3) );
		
		return str.substr(0, width);
	}
	return str;
}

static int help(std::string const & p) {
	std::cout << p << " [cmds] path \n"
		<< " cmds:\n"
		<< " -h : This help\n"
		<< " +v : debug/verbose\n"
		<< " -c : remove cert(0)\n"
		<< " -i : remove integrity flag\n"
		<< " -d : remove deb flag\n"
		<< " -a : remove aslr flag\n"
		<< " -l : remove large address aware flag\n"
		<< " +l : add large address aware flag\n"
		<< " +i : add integrity flag\n"
		<< " +d : add deb flag\n"
		<< " +a : add aslr flag\n"
		<< p << " +v c:\\temp\\*.exe\n"
		<< " path must be last argument\n"
		<< std::endl;
	return 0;
}

int main(int argc, char **argv)
{	
	using namespace std;
	using namespace ColorConsole;
	
	if (argc == 1) 	return help(argv[0]);
	
	char * cmd = getCmdOption(argv, argv + argc, "-h");
	if (cmd) return help(argv[0]);

	// command line options
	cmd = getCmdOption(argv, argv + argc, "+v");
	if (cmd) DEBUG = true;

	cmd = getCmdOption(argv, argv + argc, "-c");
	if (cmd) R_CERT = true;

	cmd = getCmdOption(argv, argv + argc, "-i");
	if (cmd) R_INTG = true;

	cmd = getCmdOption(argv, argv + argc, "-d");
	if (cmd) R_DEP = true;

	cmd = getCmdOption(argv, argv + argc, "-a");
	if (cmd) R_SLR = true;

	cmd = getCmdOption(argv, argv + argc, "+i");
	if (cmd) A_INTG = true;

	cmd = getCmdOption(argv, argv + argc, "+d");
	if (cmd) A_DEP = true;

	cmd = getCmdOption(argv, argv + argc, "+a");
	if (cmd) A_SLR = true;

	cmd = getCmdOption(argv, argv + argc, "-l");
	if (cmd) R_LADDR = true;

	cmd = getCmdOption(argv, argv + argc, "+l");
	if (cmd) A_LADDR = true;

	string filepath;
	char * f = argv[argc-1];
	if (!f) {
		return help(argv[0]);
	}
	else {
		filepath = f;
	}
	if (DEBUG) {
		cerr << lightGray << "flags: "
			<< (R_CERT ? "remove cert  " : "")
			<< (R_INTG ? "remove integrity flag  " : "")
			<< (R_DEP ? "remove dep flag  " : "")
			<< (R_SLR ? "remove aslr flag  " : "")
			<< (R_LADDR ? "remove large address flag  " : "")
			<< (A_INTG ? "add integrity flag  " : "")
			<< (A_DEP ? "add dep flag  " : "")
			<< (A_SLR ? "add aslr flag  " : "")
			<< (A_LADDR ? "add large address flag  " : "")
			<< filepath << endl;
	}

	bool state = (R_CERT | R_INTG | R_DEP | R_SLR | R_LADDR | A_INTG | A_DEP | A_SLR | A_LADDR) & true;
	string mode = state ? "WORK  " : "CHECK ";

	cout << white << darkGray_bg << "                                              SnakeOil remover                                                " 
         << red << mode << black_bg << lightGray << endl;

	win32_file_iterator itBegin(filepath,true, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_COMPRESSED), itEnd;	
	vector<string> fileNames(itBegin, itEnd);
 
	vector<string> notp;
	
	const int FIXED_FN = 73;
	cout << yellow << "Filenames" << setw(FIXED_FN-2) << "Cert  " << "LADDR  INTG  ASLR  DEP  BASE-Addr." << black_bg << lightGray  << endl;	

	for (auto & fn : fileNames) {
		auto retVal = work(fn, state);
		if (retVal.okay) {
			cout << lightGray << setw(FIXED_FN) << left << truncate(fn.c_str(), FIXED_FN) << " " << setw(2) << left
				<< (retVal.numCerts != retVal.p.numCerts ? green<char, char_traits<char>> : lightGray<char, char_traits<char>>)
				<< (retVal.numCerts != retVal.p.numCerts ? retVal.p.numCerts : retVal.numCerts)
				<< lightGray << "    "
				<< (retVal.p.laddr_s ? green<char, char_traits<char>> : (retVal.p.laddr_r ? green<char, char_traits<char>> : lightGray<char, char_traits<char>>))
				<< (retVal.p.laddr_s ? "1" : (retVal.p.laddr_r ? "0" : retVal.laddr ? "1" : "0"))
				<< lightGray << "      "
				<< (retVal.p.intg_s ? green<char, char_traits<char>> : (retVal.p.intg_r ? green<char, char_traits<char>> : lightGray<char, char_traits<char>>))
				<< (retVal.p.intg_s ? "1" : (retVal.p.intg_r ? "0" : retVal.intg ? "1" : "0"))
				<< lightGray << "     "
				<< (retVal.p.aslr_s ? green<char, char_traits<char>> : (retVal.p.aslr_r ? green<char, char_traits<char>> : lightGray<char, char_traits<char>>))
				<< (retVal.p.aslr_s ? "1" : (retVal.p.aslr_r ? "0" : retVal.aslr ? "1" : "0"))
				<< lightGray << "     "
				<< (retVal.p.dep_s ? green<char, char_traits<char>> : (retVal.p.dep_r ? green<char, char_traits<char>> : lightGray<char, char_traits<char>>))
				<< (retVal.p.dep_s ? "1" : (retVal.p.dep_r ? "0" : retVal.dep ? "1" : "0"))
				<< lightGray << "    " << "0x" << right << setfill('0') << setw(10) << hex << retVal.baseaddress << setfill(' ') << black_bg << endl;
		}
		else {
			notp.push_back(fn);
		}
	}
	if(!notp.empty())
		cout << white << "\nNot processed:" << endl;
	for (auto & fn : notp) {
		cout << lightBlue << fn << endl;
	}
	cout << lightGray;
}

