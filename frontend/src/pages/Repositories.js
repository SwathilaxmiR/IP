import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Plus, GitBranch, AlertTriangle, Calendar, Search, Github, Settings, Loader2, CheckCircle, ExternalLink, Lock, Unlock, X, RefreshCw } from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '../components/ui/dialog';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import { Checkbox } from '../components/ui/checkbox';
import { ScrollArea } from '../components/ui/scroll-area';
import { api } from '../services/api';
import { toast } from 'sonner';

const Repositories = () => {
  const [searchParams] = useSearchParams();
  const [repositories, setRepositories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [showManageDialog, setShowManageDialog] = useState(false);
  const [newRepo, setNewRepo] = useState({
    name: '',
    full_name: '',
    description: '',
    language: '',
    url: ''
  });

  // GitHub related states
  const [githubConnected, setGithubConnected] = useState(false);
  const [githubUsername, setGithubUsername] = useState('');
  const [githubLoading, setGithubLoading] = useState(false);
  const [githubRepos, setGithubRepos] = useState([]);
  const [selectedRepos, setSelectedRepos] = useState([]);
  const [repoSearchTerm, setRepoSearchTerm] = useState('');
  const [savingRepos, setSavingRepos] = useState(false);
  const [hasInstallation, setHasInstallation] = useState(false);
  const [installUrl, setInstallUrl] = useState('');

  useEffect(() => {
    fetchRepositories();
    checkGitHubConnection();
    
    // Check if redirected from GitHub OAuth callback
    if (searchParams.get('github_connected') === 'true') {
      toast.success('GitHub connected successfully!');
      checkGitHubConnection();
    }
  }, [searchParams]);

  const fetchRepositories = async () => {
    try {
      const data = await api.getRepositories();
      setRepositories(data);
    } catch (error) {
      toast.error('Failed to load repositories');
    } finally {
      setLoading(false);
    }
  };

  const checkGitHubConnection = async () => {
    try {
      const status = await api.getGitHubConnectionStatus();
      setGithubConnected(status.connected);
      setGithubUsername(status.github_username || '');
      setHasInstallation(status.has_installation || false);
      setInstallUrl(status.install_url || '');
      
      // If connected but no installation, try to sync it (user may have just installed)
      if (status.connected && !status.has_installation) {
        try {
          const syncResult = await api.syncGitHubInstallation();
          if (syncResult.success && syncResult.installation_id) {
            setHasInstallation(true);
            setInstallUrl('');
          }
        } catch (e) {
          // Installation not found, that's okay - user needs to install
        }
      }
    } catch (error) {
      console.error('Failed to check GitHub connection:', error);
    }
  };

  const handleConnectGitHub = async () => {
    setGithubLoading(true);
    try {
      const { auth_url } = await api.getGitHubAuthUrl();
      // Redirect to GitHub OAuth
      window.location.href = auth_url;
    } catch (error) {
      toast.error('Failed to initiate GitHub connection');
      setGithubLoading(false);
    }
  };

  const handleDisconnectGitHub = async () => {
    try {
      await api.disconnectGitHub();
      setGithubConnected(false);
      setGithubUsername('');
      setHasInstallation(false);
      setInstallUrl('');
      toast.success('GitHub disconnected');
    } catch (error) {
      toast.error('Failed to disconnect GitHub');
    }
  };

  const handleSyncInstallation = async () => {
    try {
      const result = await api.syncGitHubInstallation();
      if (result.success && result.installation_id) {
        setHasInstallation(true);
        setInstallUrl('');
        toast.success('App installation synced!');
      } else if (result.install_url) {
        toast.info('App not installed yet. Click "Install App" to add it.');
      }
    } catch (error) {
      toast.error('Failed to sync installation');
    }
  };

  const handleOpenManageDialog = async () => {
    if (!githubConnected) {
      toast.error('Please connect your GitHub account first');
      return;
    }

    setShowManageDialog(true);
    setGithubLoading(true);
    
    try {
      const repos = await api.getGitHubRepos();
      setGithubRepos(repos);
      // Pre-select already connected repos
      const connectedIds = repos.filter(r => r.is_connected).map(r => r.github_id);
      setSelectedRepos(connectedIds);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to fetch GitHub repositories');
      setShowManageDialog(false);
    } finally {
      setGithubLoading(false);
    }
  };

  const handleRepoSelection = (githubId) => {
    setSelectedRepos(prev => {
      if (prev.includes(githubId)) {
        return prev.filter(id => id !== githubId);
      }
      return [...prev, githubId];
    });
  };

  const handleSaveRepoSelection = async () => {
    setSavingRepos(true);
    try {
      // Find repos to connect (selected but not already connected)
      const currentlyConnected = githubRepos.filter(r => r.is_connected).map(r => r.github_id);
      const toConnect = selectedRepos.filter(id => !currentlyConnected.includes(id));
      const toDisconnect = currentlyConnected.filter(id => !selectedRepos.includes(id));

      if (toConnect.length > 0) {
        await api.connectGitHubRepos(toConnect);
      }
      if (toDisconnect.length > 0) {
        await api.disconnectGitHubRepos(toDisconnect);
      }

      toast.success('Repository selection saved');
      setShowManageDialog(false);
      fetchRepositories();
    } catch (error) {
      toast.error('Failed to save repository selection');
    } finally {
      setSavingRepos(false);
    }
  };

  const handleAddRepository = async (e) => {
    e.preventDefault();
    try {
      await api.createRepository(newRepo);
      toast.success('Repository connected successfully!');
      setShowAddDialog(false);
      setNewRepo({ name: '', full_name: '', description: '', language: '', url: '' });
      fetchRepositories();
    } catch (error) {
      toast.error('Failed to connect repository');
    }
  };

  const filteredRepos = repositories.filter((repo) =>
    repo.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    repo.description?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredGithubRepos = githubRepos.filter((repo) =>
    repo.name.toLowerCase().includes(repoSearchTerm.toLowerCase()) ||
    repo.description?.toLowerCase().includes(repoSearchTerm.toLowerCase())
  );

  const getRiskBadgeColor = (score) => {
    const colors = {
      'A': 'outline',
      'B': 'secondary',
      'C': 'default',
      'D': 'default',
      'F': 'destructive'
    };
    return colors[score] || 'default';
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center min-h-[60vh]">
          <div className="animate-spin w-12 h-12 border-4 border-primary border-t-transparent rounded-full" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-8" data-testid="repositories-page">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold mb-2">Repositories</h1>
            <p className="text-muted-foreground text-lg">
              Manage your connected GitHub repositories
            </p>
          </div>
          <div className="flex gap-3">
            {githubConnected ? (
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="px-3 py-1">
                  <Github className="w-4 h-4 mr-2" />
                  @{githubUsername}
                </Badge>
                {/* Show Install App button if connected but no installation */}
                {!hasInstallation && installUrl && (
                  <>
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => window.open(installUrl, '_blank')}
                      className="bg-green-600 hover:bg-green-700"
                    >
                      <ExternalLink className="w-4 h-4 mr-2" />
                      Install App
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleSyncInstallation}
                      title="Check if app is installed"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </Button>
                  </>
                )}
                {hasInstallation && (
                  <Badge variant="secondary" className="px-2 py-1 text-green-600">
                    <CheckCircle className="w-3 h-3 mr-1" />
                    App Installed
                  </Badge>
                )}
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={handleDisconnectGitHub}
                  className="text-muted-foreground hover:text-destructive"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            ) : (
              <Button 
                variant="outline" 
                className="shadow-md" 
                onClick={handleConnectGitHub}
                disabled={githubLoading}
                data-testid="connect-github-button"
              >
                {githubLoading ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Github className="w-4 h-4 mr-2" />
                )}
                Connect GitHub
              </Button>
            )}
            <Button 
              variant="outline" 
              className="shadow-md" 
              onClick={handleOpenManageDialog}
              disabled={!githubConnected}
              data-testid="manage-repos-button"
            >
              <Settings className="w-4 h-4 mr-2" />
              Manage Repositories
            </Button>
          </div>
        </div>

        {/* Search and Connect Repository */}
        <div className="flex items-center gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search repositories..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
              data-testid="search-repos-input"
            />
          </div>
          <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
            <DialogTrigger asChild>
              <Button className="bg-primary hover:bg-primary/90 shadow-lg" data-testid="add-repo-button">
                <Plus className="w-4 h-4 mr-2" />
                Add Manually
              </Button>
            </DialogTrigger>
            <DialogContent className="glass-card">
              <DialogHeader>
                <DialogTitle>Connect New Repository</DialogTitle>
                <DialogDescription>
                  Enter your repository details to start scanning
                </DialogDescription>
              </DialogHeader>
              <form onSubmit={handleAddRepository} className="space-y-4" data-testid="add-repo-form">
                <div className="space-y-2">
                  <Label htmlFor="name">Repository Name</Label>
                  <Input
                    id="name"
                    placeholder="my-awesome-project"
                    value={newRepo.name}
                    onChange={(e) => setNewRepo({ ...newRepo, name: e.target.value })}
                    required
                    data-testid="repo-name-input"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="full_name">Full Name (owner/repo)</Label>
                  <Input
                    id="full_name"
                    placeholder="username/my-awesome-project"
                    value={newRepo.full_name}
                    onChange={(e) => setNewRepo({ ...newRepo, full_name: e.target.value })}
                    required
                    data-testid="repo-fullname-input"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="url">Repository URL</Label>
                  <Input
                    id="url"
                    placeholder="https://github.com/username/repo"
                    value={newRepo.url}
                    onChange={(e) => setNewRepo({ ...newRepo, url: e.target.value })}
                    required
                    data-testid="repo-url-input"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="language">Primary Language</Label>
                  <Input
                    id="language"
                    placeholder="JavaScript"
                    value={newRepo.language}
                    onChange={(e) => setNewRepo({ ...newRepo, language: e.target.value })}
                    data-testid="repo-language-input"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="description">Description (optional)</Label>
                  <Input
                    id="description"
                    placeholder="Brief description"
                    value={newRepo.description}
                    onChange={(e) => setNewRepo({ ...newRepo, description: e.target.value })}
                    data-testid="repo-description-input"
                  />
                </div>
                <Button type="submit" className="w-full" data-testid="submit-repo-button">
                  Connect Repository
                </Button>
              </form>
            </DialogContent>
          </Dialog>
        </div>

        {/* Manage GitHub Repositories Dialog */}
        <Dialog open={showManageDialog} onOpenChange={setShowManageDialog}>
          <DialogContent className="max-w-2xl max-h-[80vh]">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Github className="w-5 h-5" />
                Select Repositories to Connect
              </DialogTitle>
              <DialogDescription>
                Choose which GitHub repositories you want to scan with Fixora
              </DialogDescription>
            </DialogHeader>
            
            {githubLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <>
                <div className="relative mb-4">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    placeholder="Search repositories..."
                    value={repoSearchTerm}
                    onChange={(e) => setRepoSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
                
                <ScrollArea className="h-[400px] pr-4">
                  <div className="space-y-2">
                    {filteredGithubRepos.length === 0 ? (
                      <p className="text-center text-muted-foreground py-8">
                        No repositories found
                      </p>
                    ) : (
                      filteredGithubRepos.map((repo) => (
                        <div
                          key={repo.github_id}
                          className={`flex items-center gap-4 p-4 rounded-lg border transition-colors cursor-pointer ${
                            selectedRepos.includes(repo.github_id)
                              ? 'border-primary bg-primary/5'
                              : 'border-border hover:border-muted-foreground/50'
                          }`}
                          onClick={() => handleRepoSelection(repo.github_id)}
                        >
                          <Checkbox
                            checked={selectedRepos.includes(repo.github_id)}
                            onCheckedChange={() => handleRepoSelection(repo.github_id)}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium truncate">{repo.name}</span>
                              {repo.private ? (
                                <Lock className="w-3 h-3 text-muted-foreground" />
                              ) : (
                                <Unlock className="w-3 h-3 text-muted-foreground" />
                              )}
                              {repo.is_connected && (
                                <Badge variant="outline" className="text-xs">
                                  <CheckCircle className="w-3 h-3 mr-1" />
                                  Connected
                                </Badge>
                              )}
                            </div>
                            <p className="text-sm text-muted-foreground truncate mt-1">
                              {repo.description || 'No description'}
                            </p>
                            <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                              {repo.language && (
                                <span className="flex items-center gap-1">
                                  <span className="w-2 h-2 rounded-full bg-primary" />
                                  {repo.language}
                                </span>
                              )}
                              <span>⭐ {repo.stargazers_count}</span>
                            </div>
                          </div>
                          <a
                            href={repo.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="text-muted-foreground hover:text-foreground"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        </div>
                      ))
                    )}
                  </div>
                </ScrollArea>

                <div className="flex items-center justify-between pt-4 border-t">
                  <span className="text-sm text-muted-foreground">
                    {selectedRepos.length} repositories selected
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      onClick={() => setShowManageDialog(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={handleSaveRepoSelection}
                      disabled={savingRepos}
                    >
                      {savingRepos ? (
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      ) : null}
                      Save Selection
                    </Button>
                  </div>
                </div>
              </>
            )}
          </DialogContent>
        </Dialog>

        {/* Repository List */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredRepos.length === 0 ? (
            <Card className="col-span-full">
              <CardContent className="py-12 text-center">
                <GitBranch className="w-16 h-16 mx-auto mb-4 opacity-50 text-muted-foreground" />
                <p className="text-lg text-muted-foreground">
                  {searchTerm ? 'No repositories found' : 'No repositories connected yet'}
                </p>
                <p className="text-sm text-muted-foreground mt-2">
                  {!searchTerm && (githubConnected 
                    ? 'Click "Manage Repositories" to select repositories from GitHub' 
                    : 'Connect your GitHub account to get started')}
                </p>
                {!searchTerm && !githubConnected && (
                  <Button 
                    className="mt-4"
                    onClick={handleConnectGitHub}
                    disabled={githubLoading}
                  >
                    {githubLoading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Github className="w-4 h-4 mr-2" />
                    )}
                    Connect GitHub
                  </Button>
                )}
              </CardContent>
            </Card>
          ) : (
            filteredRepos.map((repo, index) => (
              <motion.div
                key={repo.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: index * 0.05 }}
              >
                <Link to={`/repositories/${repo.id}`}>
                  <Card className="hover:border-primary/50 transition-all hover:-translate-y-1 cursor-pointer" data-testid={`repo-card-${index}`}>
                    <CardHeader>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <CardTitle className="text-xl mb-1 flex items-center gap-2">
                            {repo.name}
                            {repo.source === 'github' && (
                              <Github className="w-4 h-4 text-muted-foreground" />
                            )}
                          </CardTitle>
                          <CardDescription className="text-xs">{repo.full_name}</CardDescription>
                        </div>
                        <Badge variant={getRiskBadgeColor(repo.risk_score)}>
                          {repo.risk_score}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm text-muted-foreground mb-4 line-clamp-2">
                        {repo.description || 'No description available'}
                      </p>
                      <div className="flex items-center justify-between text-sm">
                        <div className="flex items-center gap-4">
                          {repo.language && (
                            <span className="text-muted-foreground">{repo.language}</span>
                          )}
                          <div className="flex items-center gap-1 text-destructive">
                            <AlertTriangle className="w-4 h-4" />
                            <span>{repo.total_vulnerabilities || 0}</span>
                          </div>
                        </div>
                        {repo.last_scan && (
                          <div className="flex items-center gap-1 text-muted-foreground text-xs">
                            <Calendar className="w-3 h-3" />
                            <span>{new Date(repo.last_scan).toLocaleDateString()}</span>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              </motion.div>
            ))
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Repositories;
