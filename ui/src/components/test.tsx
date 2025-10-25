import { render, screen } from '@testing-library/react'

import App from './App'

describe('<App />', () => {
  it('should render the App', () => {
    render(<App />)

    // Heading
    expect(
      screen.getByRole('heading', {
        name: /Configure Guard/i,
        level: 1
      })
    ).toBeInTheDocument()

    // Base URL input and Auth Mode select present
    expect(screen.getByTestId('base-url-input')).toBeInTheDocument()
    expect(screen.getByTestId('auth-mode-select')).toBeInTheDocument()

    // Save button initially disabled (no base URL)
    const saveBtn = screen.getByTestId('save-config') as HTMLButtonElement
    expect(saveBtn).toBeInTheDocument()
    expect(saveBtn.disabled).toBe(true)
  })
})
