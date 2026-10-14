#include "WindowsUpdateCollector.h"
#include "PersistenceCollector.h"
#include <wuapi.h>
#include <comdef.h>
#include <wrl.h>
#include <algorithm>
#include <unordered_set>

#pragma comment(lib, "wuguid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace sa {
namespace {
using Microsoft::WRL::ComPtr;

struct Bstr {
    BSTR value = nullptr;
    ~Bstr() { ::SysFreeString(value); }
    Bstr() = default;
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    std::wstring str() const { return value ? std::wstring(value, ::SysStringLen(value)) : std::wstring{}; }
};

Status ComStatus(HRESULT hr) {
    return hr == E_ACCESSDENIED || hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)
        ? Status::AccessDenied : Status::Unavailable;
}

std::wstring ErrorCode(HRESULT hr) {
    wchar_t code[16]{};
    swprintf_s(code, L"0x%08X", static_cast<unsigned>(hr));
    return code;
}

void PendingFailure(WindowsUpdateInfo& info, HRESULT hr, const wchar_t* operation) {
    if (SUCCEEDED(hr)) hr = E_UNEXPECTED;
    info.pendingStatus = ComStatus(hr);
    info.pendingReason = std::wstring(operation) + L" failed (" + ErrorCode(hr) + L").";
}

std::wstring DateUtc(DATE date) {
    SYSTEMTIME time{};
    if (!::VariantTimeToSystemTime(date, &time)) return {};
    wchar_t text[32]{};
    swprintf_s(text, L"%04u-%02u-%02uT%02u:%02u:%02uZ", time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond);
    return text;
}

const wchar_t* OperationName(OperationResultCode result) {
    switch (result) {
    case orcSucceeded: return L"Succeeded";
    case orcSucceededWithErrors: return L"Succeeded with errors";
    case orcFailed: return L"Failed";
    case orcAborted: return L"Aborted";
    case orcInProgress: return L"In progress";
    default: return L"Unknown";
    }
}

void ReadUpdateTypes(IUpdate* update, WindowsUpdateItem& item) {
    UpdateType type{};
    if (SUCCEEDED(update->get_Type(&type))) {
        if (type == utSoftware) item.updateType = L"Software";
        else if (type == utDriver) item.updateType = L"Driver";
    }
    Bstr severity;
    if (SUCCEEDED(update->get_MsrcSeverity(&severity.value))) item.severity = severity.str();
    ComPtr<ICategoryCollection> categories;
    if (FAILED(update->get_Categories(categories.GetAddressOf())) || !categories) return;
    LONG count = 0;
    if (FAILED(categories->get_Count(&count)) || count < 0) return;
    for (LONG i = 0; i < count; ++i) {
        ComPtr<ICategory> category;
        if (FAILED(categories->get_Item(i, category.GetAddressOf())) || !category) continue;
        Bstr name, categoryType;
        if (FAILED(category->get_Name(&name.value)) || FAILED(category->get_Type(&categoryType.value))) continue;
        const auto label = name.str();
        if (label.empty()) continue;
        auto* labels = IEquals(categoryType.str(), L"UpdateClassification") ? &item.classifications
            : IEquals(categoryType.str(), L"Product") ? &item.products : nullptr;
        if (labels && std::none_of(labels->begin(), labels->end(), [&](const auto& existing) { return IEquals(existing, label); }))
            labels->push_back(label);
    }
}

class SearchCompleted final : public Microsoft::WRL::RuntimeClass<
    Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>, ISearchCompletedCallback,
    Microsoft::WRL::FtmBase> {
    WinHandle event_{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
public:
    HANDLE event() const { return event_.get(); }
    HRESULT STDMETHODCALLTYPE Invoke(ISearchJob*, ISearchCompletedCallbackArgs*) override {
        return ::SetEvent(event_.get()) ? S_OK : HRESULT_FROM_WIN32(::GetLastError());
    }
};

void ReadDatesAndReboot(WindowsUpdateInfo& info) {
    ComPtr<ISystemInformation> system;
    if (SUCCEEDED(::CoCreateInstance(__uuidof(SystemInformation), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(ISystemInformation), reinterpret_cast<void**>(system.GetAddressOf()))) && system) {
        VARIANT_BOOL reboot = VARIANT_FALSE;
        if (SUCCEEDED(system->get_RebootRequired(&reboot)))
            info.rebootRequired = reboot == VARIANT_FALSE ? Tri::No : Tri::Yes;
    }
    ComPtr<IAutomaticUpdates2> automatic;
    if (FAILED(::CoCreateInstance(__uuidof(AutomaticUpdates), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IAutomaticUpdates2), reinterpret_cast<void**>(automatic.GetAddressOf()))) || !automatic) return;
    ComPtr<IAutomaticUpdatesResults> results;
    if (FAILED(automatic->get_Results(results.GetAddressOf())) || !results) return;
    _variant_t date;
    if (SUCCEEDED(results->get_LastSearchSuccessDate(&date)) && date.vt == VT_DATE)
        info.lastSearchUtc = DateUtc(date.date);
}

void ReadHistory(IUpdateSearcher* searcher, WindowsUpdateInfo& info) {
    LONG total = 0;
    HRESULT hr = searcher->GetTotalHistoryCount(&total);
    if (FAILED(hr) || total < 0) { info.historyStatus = ComStatus(hr); return; }
    if (!total) { info.historyStatus = Status::NotFound; return; }
    // History is newest-first. Ignore non-installation operations and inspect a bounded window.
    ComPtr<IUpdateHistoryEntryCollection> history;
    hr = searcher->QueryHistory(0, (std::min)(total, 64L), history.GetAddressOf());
    if (FAILED(hr) || !history) { info.historyStatus = ComStatus(hr); return; }
    LONG count = 0;
    hr = history->get_Count(&count);
    if (FAILED(hr) || count < 0) { info.historyStatus = ComStatus(hr); return; }
    info.historyStatus = Status::NotFound;
    for (LONG i = 0; i < count; ++i) {
        ComPtr<IUpdateHistoryEntry> entry;
        hr = history->get_Item(i, entry.GetAddressOf());
        if (FAILED(hr) || !entry) { info.historyStatus = Status::Unavailable; return; }
        UpdateOperation operation{};
        if (FAILED(entry->get_Operation(&operation))) { info.historyStatus = Status::Unavailable; return; }
        if (operation != uoInstallation) continue;
        Bstr title;
        if (SUCCEEDED(entry->get_Title(&title.value))) info.lastInstallationTitle = title.str();
        DATE date = 0;
        if (SUCCEEDED(entry->get_Date(&date))) info.lastInstallationUtc = DateUtc(date);
        OperationResultCode result{};
        if (FAILED(entry->get_ResultCode(&result))) { info.historyStatus = Status::Unavailable; return; }
        info.lastInstallationResult = OperationName(result);
        if (result == orcSucceeded) info.lastInstallationSucceeded = Tri::Yes;
        else if (result == orcFailed || result == orcAborted || result == orcSucceededWithErrors)
            info.lastInstallationSucceeded = Tri::No;
        LONG error = 0;
        if (SUCCEEDED(entry->get_HResult(&error)) && error)
            info.lastInstallationError = ErrorCode(static_cast<HRESULT>(error));
        info.historyStatus = info.lastInstallationSucceeded == Tri::Unknown ? Status::Unavailable : Status::Success;
        return;
    }
}

void ReadPending(IUpdateSearcher* searcher, WindowsUpdateInfo& info) {
    // Never contact update servers or allow WUA to upgrade itself during assessment.
    HRESULT hr = searcher->put_Online(VARIANT_FALSE);
    if (SUCCEEDED(hr)) hr = searcher->put_CanAutomaticallyUpgradeService(VARIANT_FALSE);
    if (FAILED(hr)) { PendingFailure(info, hr, L"Local update search configuration"); return; }
    auto callback = Microsoft::WRL::Make<SearchCompleted>();
    if (!callback || !callback->event()) { PendingFailure(info, E_OUTOFMEMORY, L"Update search callback"); return; }
    _bstr_t criteria(L"IsInstalled=0 and IsHidden=0");
    _variant_t state;
    ComPtr<ISearchJob> job;
    hr = searcher->BeginSearch(criteria, static_cast<ISearchCompletedCallback*>(callback.Get()), state, job.GetAddressOf());
    if (FAILED(hr) || !job) { PendingFailure(info, hr, L"Local update search"); return; }
    HANDLE event = callback->event();
    DWORD signaled = 0;
    hr = ::CoWaitForMultipleHandles(COWAIT_DISPATCH_CALLS, 45000, 1, &event, &signaled);
    if (FAILED(hr)) {
        (void)job->RequestAbort();
        // The callback owns its event and has no reference to the job, so a late
        // completion stays safe. CleanUp would wait without a timeout here.
        PendingFailure(info, hr, L"Local update search wait");
        if (hr == RPC_S_CALLPENDING)
            info.pendingReason = L"Local update search timed out after 45 seconds; pending updates are unknown.";
        return;
    }
    ComPtr<ISearchResult> result;
    hr = searcher->EndSearch(job.Get(), result.GetAddressOf());
    (void)job->CleanUp();
    if (FAILED(hr) || !result) { PendingFailure(info, hr, L"Local update search results"); return; }
    OperationResultCode code{};
    hr = result->get_ResultCode(&code);
    if (FAILED(hr) || code != orcSucceeded) {
        PendingFailure(info, FAILED(hr) ? hr : E_FAIL, L"Complete local update search"); return;
    }
    ComPtr<IUpdateCollection> updates;
    hr = result->get_Updates(updates.GetAddressOf());
    if (FAILED(hr) || !updates) { PendingFailure(info, hr, L"Pending update collection"); return; }
    LONG count = 0;
    hr = updates->get_Count(&count);
    if (FAILED(hr) || count < 0) { PendingFailure(info, hr, L"Pending update count"); return; }
    info.pendingStatus = Status::Success;
    std::unordered_set<std::wstring> seen;
    for (LONG i = 0; i < count; ++i) {
        ComPtr<IUpdate> update;
        hr = updates->get_Item(i, update.GetAddressOf());
        if (FAILED(hr) || !update) { PendingFailure(info, hr, L"Pending update read"); continue; }
        WindowsUpdateItem item;
        Bstr title, id;
        if (SUCCEEDED(update->get_Title(&title.value))) item.title = title.str();
        if (item.title.empty()) item.title = L"Unnamed update";
        ComPtr<IUpdateIdentity> identity;
        if (SUCCEEDED(update->get_Identity(identity.GetAddressOf())) && identity &&
            SUCCEEDED(identity->get_UpdateID(&id.value))) item.id = id.str();
        if (!item.id.empty() && !seen.insert(ToLower(item.id)).second) continue;
        ReadUpdateTypes(update.Get(), item);
        ComPtr<IUpdate3> modern;
        VARIANT_BOOL value = VARIANT_FALSE;
        if (SUCCEEDED(update.As(&modern)) && SUCCEEDED(modern->get_BrowseOnly(&value)))
            item.optional = value == VARIANT_FALSE ? Tri::No : Tri::Yes;
        else PendingFailure(info, E_FAIL, L"Update optional status");
        if (SUCCEEDED(update->get_IsDownloaded(&value))) item.downloaded = value == VARIANT_FALSE ? Tri::No : Tri::Yes;
        ComPtr<IStringCollection> kb;
        if (SUCCEEDED(update->get_KBArticleIDs(kb.GetAddressOf())) && kb) {
            LONG kbCount = 0;
            if (SUCCEEDED(kb->get_Count(&kbCount))) {
                for (LONG j = 0; j < kbCount; ++j) {
                    Bstr article;
                    if (SUCCEEDED(kb->get_Item(j, &article.value))) item.kbArticles.push_back(article.str());
                }
            }
        }
        if (item.optional == Tri::Yes) ++info.optionalCount;
        else ++info.pendingCount;
        info.updates.push_back(std::move(item));
    }
    std::sort(info.updates.begin(), info.updates.end(), [](const auto& a, const auto& b) {
        return ToLower(a.title) < ToLower(b.title);
    });
}
} // namespace

WindowsUpdateInfo CollectWindowsUpdateInfo() {
    WindowsUpdateInfo info;
    info.services = CollectServices({L"wuauserv", L"BITS", L"UsoSvc", L"WaaSMedicSvc", L"DoSvc", L"CryptSvc", L"TrustedInstaller"});
    ComInit com;
    if (!com.ok()) { info.pendingReason = L"COM initialization failed."; return info; }
    ReadDatesAndReboot(info);
    ComPtr<IUpdateSession> session;
    HRESULT hr = ::CoCreateInstance(__uuidof(UpdateSession), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IUpdateSession), reinterpret_cast<void**>(session.GetAddressOf()));
    if (FAILED(hr) || !session) { PendingFailure(info, hr, L"Windows Update Agent connection"); info.status = info.pendingStatus; return info; }
    _bstr_t client(L"SecurityAssessment");
    (void)session->put_ClientApplicationID(client);
    ComPtr<IUpdateSearcher> searcher;
    hr = session->CreateUpdateSearcher(searcher.GetAddressOf());
    if (FAILED(hr) || !searcher) { PendingFailure(info, hr, L"Windows Update Agent searcher"); info.status = info.pendingStatus; return info; }
    ReadHistory(searcher.Get(), info);
    ReadPending(searcher.Get(), info);
    info.status = info.pendingStatus;
    if (info.status == Status::Success && (info.services.status != Status::Success ||
        info.rebootRequired == Tri::Unknown || info.historyStatus == Status::Unavailable || info.historyStatus == Status::AccessDenied))
        info.status = Status::Unavailable;
    return info;
}
} // namespace sa
