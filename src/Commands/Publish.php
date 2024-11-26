<?php

declare(strict_types=1);

namespace CodeIgniter\Shield\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use CodeIgniter\Shield\Commands\Setup\ContentReplacer;
use Throwable;

class Publish extends BaseCommand
{
    /**
     * The group the command is lumped under
     * when listing commands.
     *
     * @var string
     */
    protected $group = 'Shield';

    /**
     * The Command's name
     *
     * @var string
     */
    protected $name = 'shield:publish';

    /**
     * the Command's short description
     *
     * @var string
     */
    protected $description = 'It helps you to order views or model.';

    /**
     * the Command's usage
     *
     * @var string
     */
    protected $usage = 'shield:publish [<name>]';

    /**
     * the Command's Arguments
     *
     * @var array<string, string>
     */
    protected $arguments = [
        'view'  => 'If you plan to customize the Shield views.',
        'model' => 'If you plan to customize the UserModel.',
    ];

    protected $defaultViewsPath = VENDORPATH . 'codeigniter4/shield/src/Views';
    private ContentReplacer $replacer;

    /**
     * Displays the help for the spark cli script itself.
     */
    public function run(array $params): void
    {
        $this->replacer = new ContentReplacer();

        if (current($params) === 'view') {
            $this->publishViews();

            exit;
        }

        if (current($params) === 'model') {
            $this->publishUserModel();

            exit;
        }

        if (! array_key_exists(current($params), $this->arguments)) {
            $postedArgument = CLI::promptByKey(
                ['Here is the list of your choice:', 'What do you want to do?'],
                $this->arguments,
                'required'
            );

            if ($postedArgument === 'view') {
                $this->publishViews();

                exit;
            }

            if ($postedArgument === 'model') {
                $this->publishUserModel();

                exit;
            }
        }
    }

    private function publishViews(): void
    {
        $this->checkShieldIsSetup();
        $this->copyAndPasteViews();
        $this->setCustomViewsInAuth();
    }

    private function checkShieldIsSetup(): void
    {
        $path      = APPPATH . 'Config/Auth.php';
        $cleanPath = clean_path($path);
        if (! is_file($path)) {
            CLI::error("  Error: Not found file '{$cleanPath}'.");

            exit;
        }
    }

    private function copyAndPasteViews(): void
    {
        $copyFrom = $this->defaultViewsPath;

        $pasteTo = APPPATH . 'Views/Shield/';

        try {
            directory_mirror($copyFrom, $pasteTo);
            CLI::write(CLI::color('  Copy Views: ', 'green') . 'All files copy to "App/Views/Shield".');
        } catch (Throwable $e) {
            CLI::error('  Error. There was a problem with the copy original views.');
        }
    }

    private function setCustomViewsInAuth(): void
    {
        $path = APPPATH . 'Config/Auth.php';

        $replaces = [
            '\CodeIgniter\Shield\Views\login'                      => '\App\Views\Shield\login',
            '\CodeIgniter\Shield\Views\register'                   => '\App\Views\Shield\register',
            '\CodeIgniter\Shield\Views\layout'                     => '\App\Views\Shield\layout',
            '\CodeIgniter\Shield\Views\email_2fa_show'             => '\App\Views\Shield\email_2fa_show',
            '\CodeIgniter\Shield\Views\email_2fa_verify'           => '\App\Views\Shield\email_2fa_verify',
            '\CodeIgniter\Shield\Views\Email\email_2fa_email'      => '\App\Views\Shield\Email\email_2fa_email',
            '\CodeIgniter\Shield\Views\Email\email_activate_email' => '\App\Views\Shield\Email\email_activate_email',
            '\CodeIgniter\Shield\Views\email_activate_show'        => '\App\Views\Shield\email_activate_show',
            '\CodeIgniter\Shield\Views\magic_link_form'            => '\App\Views\Shield\magic_link_form',
            '\CodeIgniter\Shield\Views\magic_link_message'         => '\App\Views\Shield\magic_link_message',
            '\CodeIgniter\Shield\Views\Email\magic_link_email'     => '\App\Views\Shield\Email\magic_link_email',
        ];

        $cleanPath = clean_path($path);
        $content   = file_get_contents($path);

        $output = $this->replacer->replace($content, $replaces);

        if ($output === $content) {
            CLI::write(CLI::color('  Set Views : ', 'green') . 'All views is set in file "App/Config/Auth".');

            return;
        }

        if (write_file($path, $output)) {
            CLI::write(CLI::color('  Set New Views: ', 'green') . "We have updated file '{$cleanPath}' for custoum view.");
        } else {
            CLI::error("  Error updating file '{$cleanPath}'.");
        }
    }

    private function publishUserModel(): void
    {
        $content = <<<'TPLMODEL'
            <?php

            declare(strict_types=1);

            namespace App\Models;

            use CodeIgniter\Shield\Models\UserModel;

            class CustomModel extends UserModel
            {
                protected function initialize(): void
                {
                    // Merge properties with parent
                    $this->allowedFields = array_merge($this->allowedFields, [
                        // Add here your custom fields
                        // 'first_name',

                    ]);
                }
            }
            TPLMODEL;

        $modelName = CLI::prompt('Please enter your model name?', null, 'required');

        $output = $this->replacer->replace($content, ['CustomModel' => $modelName]);

        $path = APPPATH . "Models/{$modelName}.php";

        $cleanPath = clean_path($path);

        if (write_file($path, $output, 'x')) {
            CLI::write(CLI::color('  Done: ', 'green') . "The model was created in path '{$cleanPath}'.");
        } else {
            CLI::error("  Error created file '{$cleanPath}'.");
        }
    }
}
