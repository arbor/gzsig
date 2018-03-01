if [ "$_system_type" == "Darwin" ]; then
  sed () {
    gsed "$@"
  }
fi

_project="$CIRCLE_PROJECT_REPONAME"
_version=$(cat VERSION)

_branch=$(git rev-parse --abbrev-ref HEAD)
_branch_prefix=${_branch%-branch}

if [[ $(git ls-remote origin "refs/tags/v$_version") ]]; then
  echo "The tag v$_version already exists.  Will not tag"
  exit 0
fi

_commit=$(git rev-parse --verify HEAD)

_release_data=$(cat <<EOF
{
  "tag_name": "v$_version",
  "target_commitish": "$_commit",
  "name": "v$_version",
  "body": "New release",
  "draft": false,
  "prerelease": false
}
EOF
)

echo "Creating release v$_version from commit $_commit in branch $_branch"

set -x

_release=$(
  curl -H "Authorization: token $GITHUB_TOKEN" \
    -X POST https://api.github.com/repos/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/releases \
    --data "$_release_data"
)

_release_id=$(
  echo "$_release" | grep -m 1 "id.:" | grep -w id | tr : = | tr -cd '[[:alnum:]]=' | cut -d '=' -f 2
)

_arch=$(uname)
_bin_dir=/usr/local/bin/
_package="$_arch.$_project.tar.gz"

tar -zcvf /tmp/$_package -C $_bin_dir .


curl -H "Authorization: token $GITHUB_TOKEN" \
  -H "Content-Type: application/octet-stream" \
  -X POST https://uploads.github.com/repos/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME/releases/$_release_id/assets?name=$_package \
  --data-binary @/tmp/$_package
