# Windows Versions - Check for Min of Win 2012
# Win2016 - NT 10.0 | Win 2012 R2 - NT 6.3 | Win 2012 - NT 6.2
#

control 'WINDOWS VERSION' do
  impact 0.8
  title 'This test checks for a minimum Windows version of 2012 - NT 6.2.0'

  describe os.family do
    it { should eq 'windows' }
  end

  describe os.name do
    it { should eq 'windows_server_2016_datacenter' }
  end

  describe os.release do
    it { should > '10.0' }
  end
end

## Looping example WannaCry Vulnerability Check
control 'WINDOWS HOTFIX - LOOP' do
  impact 0.8
  title 'This test checks that a numberof Windows Hotfixs are installed - Looping Example'

  hotfixes = %w{ KB4012598 KB4042895 KB4041693 }

  describe.one do
    hotfixes.each do |hotfix|
      describe windows_hotfix(hotfix) do
        it { should_not be_installed }
      end
    end
  end
end

control 'PACKAGE INSTALLED _ TELNET and CHROME' do
  impact 0.8
  title 'This test checks that a package is installed'

  describe package('telnetd') do
    it { should_not be_installed }
  end

  describe package('Google Chrome') do
    it { should be_installed}
  end
end

## service example
control 'SERVICE INSTALLED' do
  impact 0.8
  title 'This test checks the service is installed'

  describe service('DHCP Client') do
    it { should be_installed }
    it { should be_running }
  end
end

control 'HTTP AND HTTPS' do
  impact 0.8
  title 'This test checks the HTTP and HTTPS protocols'
  
  # Test HTTP port 80, is not listening and no protocol TCP, ICMP, UDP
  describe port(80) do
      it { should_not be_listening }
      its('protocols') { should_not cmp 'tcp6' }
      its('protocols') { should_not include('icmp') }
      its('protocols') { should_not include('tcp') }
      its('protocols') { should_not include('udp') }
      its('protocols') { should_not include('udp6') }
      its('addresses') { should_not include '0.0.0.0' }
  end

  # Test HTTPS port 443, listening with TCP and UDP
  describe port(443) do
      it { should be_listening }
      its('protocols') { should_not cmp 'tcp6' }
      its('protocols') { should_not include('icmp') }
      its('protocols') { should include('tcp') }
      its('protocols') { should include('udp') }
      its('protocols') { should_not include('udp6') }
      its('addresses') { should include '0.0.0.0' }
  end
end

control 'WINDOWS TASKS' do
  impact 0.8
  title 'This test checks the Windows Tasks'
  
  describe windows_task('\Microsoft\Windows\AppID\PolicyConverter') do
    it { should be_disabled }
  end

  describe windows_task('\Microsoft\Windows\AppID\PolicyConverter') do
    its('logon_mode') { should eq 'Interactive/Background' }
    its('last_result') { should eq '267011' }
    its('task_to_run') { should cmp '%Windir%\system32\appidpolicyconverter.exe' }
    its('run_as_user') { should eq 'SYSTEM' }
  end

  describe windows_task('\Microsoft\Windows\Defrag\ScheduledDefrag') do
    it { should exist }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE" do
  title "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc  "The \"Process even if the Group Policy objects have not changed\" option updates and reapplies policies even if the policies have not changed."
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should_not have_property "NoGPOListChanges" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    its("NoGPOListChanges") { should_not cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.4_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc  "This policy setting prevents Group Policy from being updated while the computer is in use."
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should_not have_property "DisableBkGndGroupPolicy" }
  end
end