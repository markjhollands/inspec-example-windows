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