import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Github, Save } from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { toast } from 'sonner';

const Settings = () => {
  const [githubToken, setGithubToken] = useState('');

  const handleSaveGithubToken = () => {
    toast.info('GitHub token will be configured on backend');
  };

  return (
    <DashboardLayout>
      <div className="space-y-8" data-testid="settings-page">
        <div>
          <h1 className="text-4xl font-bold mb-2">Settings</h1>
          <p className="text-muted-foreground text-lg">
            Manage API keys and configurations
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: 0.1 }}
          >
            <Card className="glass-card">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Github className="w-5 h-5 text-primary" />
                  <CardTitle>GitHub Personal Access Token</CardTitle>
                </div>
                <CardDescription>
                  Configure GitHub token for repository access and PR creation
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="github-token">Personal Access Token</Label>
                  <Input
                    id="github-token"
                    type="password"
                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxxx"
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    data-testid="github-token-input"
                  />
                  <p className="text-xs text-muted-foreground">
                    Create token at{' '}
                    <a
                      href="https://github.com/settings/tokens"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      GitHub Settings
                    </a>
                    <br />
                    Required scopes: repo, read:user
                  </p>
                </div>
                <Button onClick={handleSaveGithubToken} className="w-full" data-testid="save-github-token-btn">
                  <Save className="w-4 h-4 mr-2" />
                  Save Token
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        </div>

        <Card className="glass-card">
          <CardHeader>
            <CardTitle>Setup Instructions</CardTitle>
            <CardDescription>Follow these steps to get started</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4 text-sm">
              <div>
                <h4 className="font-semibold mb-2">1. GitHub Token Setup</h4>
                <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                  <li>Go to GitHub Settings → Developer settings → Personal access tokens</li>
                  <li>Generate new token (classic)</li>
                  <li>Select scopes: repo (Full control), read:user</li>
                  <li>Copy and paste the token above</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2">2. Connect Repositories</h4>
                <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                  <li>Go to Repositories page</li>
                  <li>Click "Connect Repository"</li>
                  <li>Enter your repository details</li>
                  <li>Start scanning!</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
