import React from 'react';

const EFFECTIVE_DATE = 'April 24, 2026';
const COMPANY = 'ModernEndpoint.tech';
const CONTACT_EMAIL = 'support@modernendpoint.tech';
const PRODUCT = 'Privileged Identity Monitor';

export default function TermsPage() {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#0C0C11',
        color: 'var(--text-primary, #e8e8f0)',
        fontFamily: 'var(--font-sans, system-ui, sans-serif)',
        padding: '0 16px 80px',
      }}
    >
      {/* Header */}
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '64px 0 40px' }}>
        <a
          href="/"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 40, textDecoration: 'none', color: '#E8784A', fontSize: 13, fontWeight: 600 }}
        >
          ← Back
        </a>

        <h1 style={{ fontSize: 32, fontWeight: 800, marginBottom: 8 }}>Terms of Service</h1>
        <p style={{ fontSize: 13, color: '#888', marginBottom: 48 }}>Effective date: {EFFECTIVE_DATE}</p>

        <Section title="1. About the Service">
          <p>
            {PRODUCT} ("the Service") is a cloud-based security monitoring product operated by {COMPANY}.
            The Service connects to your Microsoft 365 tenant via Microsoft Graph API to detect
            anomalous sign-in activity, privileged identity changes, and identity-based threats.
          </p>
        </Section>

        <Section title="2. Eligibility">
          <p>
            By using the Service you confirm that you are an authorized administrator of the
            Microsoft 365 tenant you connect, and that you have the right to grant the permissions
            requested during the setup process.
          </p>
        </Section>

        <Section title="3. Free Tier & Paid Subscription">
          <ul>
            <li>The Free tier provides anomaly detection and alert visibility at no cost, with no time limit.</li>
            <li>
              The Pro tier ($15 / month) adds real-time Telegram notifications, email alerts, and automated
              remediation. Payment is processed by Gumroad. By subscribing you agree to Gumroad's
              terms of service.
            </li>
            <li>You may cancel your subscription at any time from your Gumroad account. Upon cancellation,
              your account reverts to the Free tier immediately.</li>
            <li>No refunds are issued for partial billing periods.</li>
          </ul>
        </Section>

        <Section title="4. Your Data & Privacy">
          <p>
            All sign-in log data and alert data are stored in <strong>your own Azure subscription</strong>.
            {COMPANY} does not have access to your tenant data. We store only the configuration and
            metadata required to operate the Service on your behalf. See our{' '}
            <a href="/privacy" style={{ color: '#E8784A' }}>Privacy Policy</a> for details.
          </p>
        </Section>

        <Section title="5. Acceptable Use">
          <ul>
            <li>You may only use the Service to monitor tenants you are authorized to administer.</li>
            <li>You may not use the Service to monitor individuals without their organization's consent.</li>
            <li>You may not attempt to reverse-engineer, resell, or misuse the Service.</li>
          </ul>
        </Section>

        <Section title="6. Service Availability">
          <p>
            We strive for high availability but do not guarantee uninterrupted service. We reserve the
            right to modify or discontinue features with reasonable notice. We are not liable for any
            security incidents that occur during service downtime.
          </p>
        </Section>

        <Section title="7. Limitation of Liability">
          <p>
            The Service is provided "as is." {COMPANY} is not liable for any direct, indirect, or
            consequential damages arising from use of the Service, including missed detections or
            delayed alerts. Your use of the Service does not substitute for a comprehensive security
            program.
          </p>
        </Section>

        <Section title="8. Changes to Terms">
          <p>
            We may update these Terms from time to time. We will notify you by email or in-app notice.
            Continued use of the Service after changes constitutes acceptance of the new Terms.
          </p>
        </Section>

        <Section title="9. Governing Law">
          <p>These Terms are governed by the laws of the State of Israel.</p>
        </Section>

        <Section title="10. Contact">
          <p>
            Questions? Email us at{' '}
            <a href={`mailto:${CONTACT_EMAIL}`} style={{ color: '#E8784A' }}>{CONTACT_EMAIL}</a>
          </p>
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ marginBottom: 36 }}>
      <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 10, color: '#E8784A' }}>{title}</h2>
      <div style={{ fontSize: 14, color: '#bbb', lineHeight: 1.75 }}>{children}</div>
    </section>
  );
}
