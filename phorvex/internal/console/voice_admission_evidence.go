package console

import (
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	"time"
)

func voiceAdmissionSessionMatches(v voiceAdmissionSession, snap voiceAdmissionSnapshot, podUID, runSHA, callHash string, signed bool) bool {
	return v.Version == 1 && voiceadmissionpolicy.ValidUID(v.SessionID) && v.RunSHA256 == runSHA && v.CallSIDHash == callHash && v.PodUID == podUID &&
		v.DeploymentUID == snap.DeploymentUID && v.AdmissionSourceSHA256 == snap.Rule.AdmissionSourceSHA256 && v.LegacyBundleSHA256 == snap.Rule.LegacyBundleSHA256 &&
		v.AuthProfileSHA256 == snap.Rule.AuthProfileSHA256 && v.Authenticated == signed && v.ConnectedAtUnixMs > 0 && v.ObservedAtUnixMs >= v.ConnectedAtUnixMs &&
		v.AdmissionRuleSHA256 == snap.RuleSHA256 && v.AdmissionRevision == snap.Rule.Revision
}
func voiceAdmissionProviderMatches(p voiceAdmissionProvider, v voiceAdmissionSession) bool {
	return p.Version == 1 && p.SessionID == v.SessionID && p.RunSHA256 == v.RunSHA256 && p.CallSIDHash == v.CallSIDHash && p.PodUID == v.PodUID &&
		p.DeploymentUID == v.DeploymentUID && p.AdmissionSourceSHA256 == v.AdmissionSourceSHA256 && p.LegacyBundleSHA256 == v.LegacyBundleSHA256 && p.AuthProfileSHA256 == v.AuthProfileSHA256 &&
		p.ObservedAtUnixMs >= v.ConnectedAtUnixMs && p.STTFrames > 0 && p.STTFrames <= 100000 && p.ModelTextFrames > 0 && p.ModelTextFrames <= 100000 && p.ModelCompletions > 0 && p.ModelCompletions <= 16 &&
		p.TTSAudioFrames > 0 && p.TTSAudioFrames <= 100000 && p.TTSAudioBytes > 0 && p.TTSAudioBytes <= 16777216 && voiceadmissionpolicy.ValidSHA(p.STTTextSHA256) && voiceadmissionpolicy.ValidSHA(p.ModelTextSHA256) &&
		p.STTTextSHA256 != voiceMCPStringSHA("") && p.ModelTextSHA256 != voiceMCPStringSHA("")
}
func voiceAdmissionAudioObserved(v voiceAdmissionSession, p voiceAdmissionProvider) bool {
	return v.Stage == "pipeline-observed" && v.ReceivedAudioFrames > 0 && v.ReceivedAudioFrames <= 1024 && v.SentAudioFrames > 0 && v.SentAudioFrames <= 2048 && v.SentAudioBytes > 0 && v.SentAudioBytes <= 1048576 &&
		voiceAdmissionProviderMatches(p, v)
}
func voiceAdmissionFirstLoss(reply voiceAdmissionReply, snap voiceAdmissionSnapshot, podUID, run string) (time.Time, bool) {
	if reply.Version != 1 || reply.Operation != "observe" || reply.RunSHA256 != voiceMCPStringSHA(run) || reply.Client.Version != 1 || reply.Client.RunSHA256 != reply.RunSHA256 || reply.Loss == nil || reply.Client.Done || reply.Client.Error != "" || snap.Rule.Revision != 0 || snap.Rule.Mode != voiceadmissionpolicy.ModeObserve {
		return time.Time{}, false
	}
	v, p := reply.Loss.Session, reply.Loss.Provider
	if v.SessionID != reply.Client.UnsignedSessionID || !voiceAdmissionSessionMatches(v, snap, podUID, voiceMCPStringSHA(run), voiceAdmissionCallHash(run, "unsigned"), false) ||
		!voiceAdmissionAudioObserved(v, p) || v.DisconnectedAtUnixMs != 0 || v.DelegateCompleted || v.DisconnectDelivered || reply.Client.UnsignedFrames == 0 || reply.Client.UnsignedBytes == 0 {
		return time.Time{}, false
	}
	when := time.UnixMilli(v.ObservedAtUnixMs)
	age := time.Since(when)
	return when, age >= 0 && age < 50*time.Second
}
func voiceAdmissionFind(reply voiceAdmissionReply, sessionID string) (voiceAdmissionSession, voiceAdmissionProvider, bool) {
	var v voiceAdmissionSession
	var p voiceAdmissionProvider
	nv, np := 0, 0
	for _, x := range reply.Sessions {
		if x.SessionID == sessionID {
			v = x
			nv++
		}
	}
	for _, x := range reply.Providers {
		if x.SessionID == sessionID {
			p = x
			np++
		}
	}
	return v, p, nv == 1 && np == 1
}
func voiceAdmissionSignedControl(reply voiceAdmissionReply, before voiceAdmissionSnapshot, podUID, run, phase string) bool {
	id := reply.Client.SignedSessionID
	if phase == "new" {
		if len(reply.Sessions) != 1 {
			return false
		}
		id = reply.Sessions[0].SessionID
	}
	v, p, ok := voiceAdmissionFind(reply, id)
	return ok && voiceAdmissionSessionMatches(v, before, podUID, voiceMCPStringSHA(run), voiceAdmissionCallHash(run, phase), true) && voiceAdmissionAudioObserved(v, p)
}
func voiceAdmissionSessionsEnded(reply voiceAdmissionReply, first voiceAdmissionReply) bool {
	if !reply.Client.UnsignedClosed || !reply.Client.PendingClosed || reply.Client.Done || reply.Client.Error != "" {
		return false
	}
	for _, id := range []string{first.Client.UnsignedSessionID, first.Client.PendingSessionID} {
		count := 0
		for _, v := range reply.Sessions {
			if v.SessionID == id {
				count++
				if v.Authenticated || !v.DisconnectDelivered || !v.DelegateCompleted || v.DisconnectedAtUnixMs == 0 || v.Stage != "closed" {
					return false
				}
			}
		}
		if id == "" || count != 1 {
			return false
		}
	}
	return true
}
