'use client';

export default function LegalDisclaimer() {
  return (
    <footer className="fixed bottom-0 left-0 right-0 z-[9999] bg-black/80 backdrop-blur-sm border-t border-cyan-900/50 px-4 py-2 text-[10px] font-mono leading-tight text-cyan-700/60">
      <div className="max-w-full">
        <strong className="text-yellow-600/80">⚠️ LEGAL DISCLAIMER</strong>
        <br />
        DirvenScan does NOT file whistleblower claims automatically. Users must file manually through SEC/CFTC/IRS portals.
        False statements are perjury (18 U.S.C. § 1621) - up to 5 years imprisonment.
        V2K lawsuits are dismissed as &quot;fantastic or delusional.&quot; DO NOT FILE. File IIED/Extortion/Fraud instead.
        Awards are NOT guaranteed - require successful enforcement action. Processing time: 2-5 years typical.
        Consult an attorney before filing. DirvenScan takes no portion of any award.
      </div>
      <div className="mt-0.5 text-cyan-700/40">
        🔍 ShadowBrokerDirvenScan | 🌐 web3://dirvenacademy.hub | 🚢 SS Crypto Bubble
      </div>
    </footer>
  );
}
