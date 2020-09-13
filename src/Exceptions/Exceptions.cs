using System;

namespace QuickAPI.Exceptions
{
    [Serializable]
    public class QuickApiException : Exception
    {
        public QuickApiException(string message)
            : base(message)
        {
        }
    }

    [Serializable]
    public class CredentialsException : QuickApiException
    {
        public CredentialsException(string message)
            : base(message)
        {
        }
    }

    [Serializable]
    public class ParameterException : QuickApiException
    {
        public ParameterException(string message)
            : base(message)
        {
        }
    }
}
