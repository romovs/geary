/*
 * Copyright 2016 Michael Gratton <mike@vee.net>
 *
 * This software is licensed under the GNU Lesser General Public License
 * (version 2.1 or later). See the COPYING file in this distribution.
 */

// Required because Gcr's VAPI is behind-the-times
// TODO: When bindings available, use async variants of these calls
extern const string GCR_PURPOSE_SERVER_AUTH;
extern async bool gcr_trust_add_pinned_certificate_async(Gcr.Certificate cert, string purpose, string peer,
    Cancellable? cancellable) throws Error;
extern async bool gcr_trust_is_certificate_pinned_async(Gcr.Certificate cert, string purpose, string peer,
    Cancellable? cancellable) throws Error;
extern async bool gcr_trust_remove_pinned_certificate_async(Gcr.Certificate cert, string purpose, string peer,
    Cancellable? cancellable) throws Error;

/**
 * Accesses desktop-wide TLS certificate store using GCR.
 */
public class GcrService: Geary.BaseObject {

    /**
     * Determines if a TLS certificate as trusted for a specific host.
     */
    public async bool is_trusted(Geary.Endpoint target,
                                 TlsCertificate test_cert,
                                 Cancellable? cancellable = null)
    throws Error {
        Gcr.Certificate cert = new Gcr.SimpleCertificate(
            test_cert.certificate.data
        );
        string peer = to_gcr_peer(target);
        return yield gcr_trust_is_certificate_pinned_async(
            cert, GCR_PURPOSE_SERVER_AUTH, peer, cancellable
        );
    }

    /**
     * Marks a TLS certificate as trusted by pinning it.
     */
    public async void add_pinned(Geary.Endpoint target,
                                 TlsCertificate trusted_cert,
                                 Cancellable? cancellable = null)
    throws Error {
        Gcr.Certificate cert = new Gcr.SimpleCertificate(
            trusted_cert.certificate.data
        );
        string peer = to_gcr_peer(target);
        yield gcr_trust_add_pinned_certificate_async(
            cert, GCR_PURPOSE_SERVER_AUTH, peer, cancellable
        );
    }

    /**
     *  Unmarks a TLS certificate as trusted by unpinning it.
     */
    public async void remove_pinned(Geary.Endpoint target,
                                    TlsCertificate untrusted_cert,
                                    Cancellable? cancellable = null)
    throws Error {
        Gcr.Certificate cert = new Gcr.SimpleCertificate(
            untrusted_cert.certificate.data
        );
        string peer = to_gcr_peer(target);
        yield gcr_trust_remove_pinned_certificate_async(
            cert, GCR_PURPOSE_SERVER_AUTH, peer, cancellable
        );
    }

    private inline string to_gcr_peer(Geary.Endpoint host) {
        // The default GIO GNUTLS backend uses the remote address
        // hostname as the peer, so we need to here as well
        return host.remote_address.get_hostname();
    }

}
